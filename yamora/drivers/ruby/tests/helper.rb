# frozen_string_literal: true

require 'minitest/autorun'
require 'socket'
require 'tmpdir'
require 'fileutils'
require 'json'
require 'open3'
require_relative '../lib/yamora'

module DriverFixtures
  READ_TOKEN = 'r' * 32
  WRITE_TOKEN = 'w' * 32
  REV = '0123456789abcdef'
  ETAG = 'abcdef0123456789'

  def scratch
    root = scratch_root
    Dir.mktmpdir('ruby-', root) { |dir| yield dir }
  end

  def scratch_root
    output, error, status = Open3.capture3('python3', '-c',
      'import json, os; from tools.ci.yamora_driver_ci.runner import scratch_parent; print(json.dumps(str(scratch_parent(os.environ["TMPDIR"]))))')
    unless status.success?
      raise ArgumentError, "TMPDIR must name an existing owned disk-backed managed directory: #{error}"
    end
    JSON.parse(output)
  rescue SystemCallError
    raise ArgumentError, 'TMPDIR validation requires the selected Python helper', cause: nil
  end

  def reply(body = '{}', status: 200, headers: {})
    headers = { 'Content-Type' => 'application/json', 'X-YamlDB-Revision' => REV, 'Content-Length' => body.bytesize.to_s }.merge(headers)
    "HTTP/1.1 #{status} Test\r\n#{headers.map { |k, v| "#{k}: #{v}\r\n" }.join}\r\n#{body}"
  end

  # Real TCP peer: tests observe credentials, framing and request counts, and
  # can drop an acknowledgement after reading the complete mutation body.
  class Peer
    attr_reader :port, :requests

    def initialize(&handler)
      @listener = TCPServer.new('127.0.0.1', 0)
      @port = @listener.addr[1]
      raise 'owner port allocated' if @port == 8000
      @requests = []
      @errors = Queue.new
      @thread = Thread.new do
        loop do
          socket = @listener.accept
          begin
            Timeout.timeout(3) do
              first = socket.gets("\r\n")
              next unless first
              headers = {}
              while (line = socket.gets("\r\n")) && line != "\r\n"
                key, value = line.strip.split(':', 2)
                headers[key.downcase] = value.strip
              end
              size = headers.fetch('content-length', '0').to_i
              body = size.zero? ? ''.b : socket.read(size)
              @requests << [first.strip, headers, body]
              handler.call(socket, @requests.last)
            end
          ensure
            socket.close
          end
        end
      rescue IOError, Errno::EBADF
        # Listener closed by this fixture.
      rescue StandardError => error
        @errors << error
      end
      @thread.report_on_exception = false
    end

    def close
      @listener.close
      unless @thread.join(4)
        @thread.kill.join
        raise 'peer failed to stop'
      end
      raise @errors.pop unless @errors.empty?
    end
  end

  def with_peer(handler, **options)
    peer = Peer.new(&handler)
    begin
      client = Yamora::Client.new(port: peer.port, read_token: READ_TOKEN, write_token: WRITE_TOKEN, **options)
      yield client, peer
    ensure
      peer.close
    end
  end

  def certificates(dir, san: 'IP:127.0.0.1', expired: false, server_name: 'server')
    ca_key = OpenSSL::PKey::EC.generate('prime256v1')
    ca = issue_certificate('CA', ca_key, nil, nil, 1, ca: true)
    server_key = OpenSSL::PKey::EC.generate('prime256v1')
    server = issue_certificate(server_name, server_key, ca, ca_key, 2, san: san, expired: expired)
    client_key = OpenSSL::PKey::EC.generate('prime256v1')
    client = issue_certificate('client', client_key, ca, ca_key, 3, client: true)
    files = { 'ca.pem' => ca.to_pem, 'server.pem' => server.to_pem, 'server.key' => server_key.to_pem,
              'client.pem' => client.to_pem, 'client.key' => client_key.to_pem }
    files.each { |name, pem| File.write(File.join(dir, name), pem, mode: 'w', perm: 0o600) }
    files
  end

  def issue_certificate(name, key, issuer, issuer_key, serial, ca: false, client: false, san: nil, expired: false)
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = serial
    certificate.subject = OpenSSL::X509::Name.parse("/CN=#{name}")
    certificate.issuer = issuer ? issuer.subject : certificate.subject
    certificate.public_key = key
    certificate.not_before = Time.now - 3600
    certificate.not_after = Time.now + (expired ? -60 : 3600)
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = certificate
    factory.issuer_certificate = issuer || certificate
    certificate.add_extension(factory.create_extension('basicConstraints', ca ? 'CA:TRUE' : 'CA:FALSE', true))
    certificate.add_extension(factory.create_extension('keyUsage', ca ? 'keyCertSign,cRLSign' : 'digitalSignature', true))
    certificate.add_extension(factory.create_extension('extendedKeyUsage', client ? 'clientAuth' : 'serverAuth')) unless ca
    certificate.add_extension(factory.create_extension('subjectAltName', san)) if san
    certificate.sign(issuer_key || key, OpenSSL::Digest.new('SHA256'))
    certificate
  end

  def with_native(root, tls: nil, flags: [])
    binary = ENV['YAMORA_TEST_BINARY']
    skip 'Set YAMORA_TEST_BINARY to include native daemon tests' unless binary
    raise 'YAMORA_TEST_BINARY must be an absolute executable' unless binary.start_with?('/') && File.executable?(binary)
    database = File.join(root, 'database')
    Dir.mkdir(database, 0o700)
    %w[read write].zip([READ_TOKEN, WRITE_TOKEN]).each do |name, token|
      File.write(File.join(root, "#{name}.token"), token, mode: 'w', perm: 0o600)
    end
    File.open(File.join(root, 'init.log'), 'w+') do |init_log|
      init_pid = Process.spawn(binary, '--data-dir', database, '--init-disk', '--validate-only', out: init_log, err: init_log)
      begin
        _, status = Timeout.timeout(20) { Process.wait2(init_pid) }
        init_log.rewind
        raise "native initialization failed: #{init_log.read}" unless status.success?
      ensure
        stop_owned(init_pid)
      end
    end
    reader, writer = IO.pipe
    log = File.open(File.join(root, 'daemon.log'), 'w+')
    pid = Process.spawn(binary, '--data-dir', database, '--port', '0', '--workers', '4',
                        '--auth-token-file', File.join(root, 'read.token'),
                        '--write-auth-token-file', File.join(root, 'write.token'), *flags, out: writer, err: log)
    writer.close
    begin
      banner = Timeout.timeout(20) { reader.gets }
      match = /\Ayamora listening on 127\.0\.0\.1:([0-9]+) /.match(banner || '')
      unless match
        log.flush
        log.rewind
        raise "invalid daemon banner: #{banner.inspect}; #{log.read}"
      end
      port = Integer(match[1])
      raise 'owner port allocated' if port == 8000
      client = Yamora::Client.new(port: port, read_token: READ_TOKEN, write_token: WRITE_TOKEN, timeout: 5, tls: tls)
      yield client, port
    ensure
      begin
        stop_owned(pid)
      ensure
        reader.close
        log.rewind
        diagnostics = log.read
        log.close
      end
      raise "native sanitizer failure: #{diagnostics}" if diagnostics.match?(/ERROR: (AddressSanitizer|LeakSanitizer)|runtime error:/)
    end
  end

  def stop_owned(pid)
    return if Process.waitpid(pid, Process::WNOHANG)
    Process.kill('TERM', pid)
    Timeout.timeout(5) { Process.wait(pid) }
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  rescue Timeout::Error
    Process.kill('KILL', pid)
    Process.wait(pid)
  end
end
