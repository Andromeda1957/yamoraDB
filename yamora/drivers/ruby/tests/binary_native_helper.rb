# frozen_string_literal: true

require_relative 'binary_helper'

module BinaryNativeFixtures
  include BinaryFixtures

  class NativeBinary
    include BinaryFixtures
    attr_reader :port, :http_port, :http, :pem

    def initialize(root, pem, legacy: false, mtls: true, read_only: false)
      @root, @pem = root, pem
      binary = ENV.fetch('YAMORA_TEST_BINARY') { raise 'YAMORA_TEST_BINARY is required; native binary acceptance never skips' }
      raise 'absolute executable native daemon required' unless binary.start_with?('/') && File.executable?(binary)
      @binary, @digest = binary, Digest::SHA256.file(binary).hexdigest
      data = File.join(root, 'data')
      Dir.mkdir(data, 0o700)
      @log_path = File.join(root, 'stderr')
      command(binary, '--data-dir', data, '--init-disk', '--validate-only')
      legacy_image(File.join(data, '.yamora-disk')) if legacy
      { 'read.token' => READ_TOKEN, 'write.token' => WRITE_TOKEN, 'scoped.token' => 's' * 32 }.each { |name, value| write(name, value) }
      write('policy.json', JSON.generate({ 'version' => 1,
            'roles' => { 'one' => { 'read' => ['allowed'], 'write' => ['allowed'] } },
            'principals' => { 'one' => { 'token_file' => File.join(root, 'scoped.token'), 'roles' => ['one'] } } }))
      args = [binary, '--data-dir', data, '--port', '0', '--binary-port', '0', '--workers', '2', '--cache-bytes', '1048576',
              '--io-timeout-ms', '10000', '--auth-token-file', File.join(root, 'read.token'),
              '--access-policy-file', File.join(root, 'policy.json'),
              '--tls-cert-file', File.join(root, 'server.pem'), '--tls-key-file', File.join(root, 'server.key')]
      args += ['--write-auth-token-file', File.join(root, 'write.token')] unless read_only
      args += ['--tls-client-ca-file', File.join(root, 'ca.pem')] if mtls
      @reader, writer = IO.pipe
      begin
        @pid = Process.spawn(native_environment, *args, out: writer, err: @log_path)
      ensure
        writer.close
      end
      lines = Timeout.timeout(15) { [@reader.gets, @reader.gets] }
      http = /\Ayamora listening on 127\.0\.0\.1:([0-9]+) /.match(lines[0] || '')
      binary = /\Abinary listening on 127\.0\.0\.1:([0-9]+)/.match(lines[1] || '')
      raise "required native binary listener absent: #{lines.inspect}; #{File.read(@log_path)}" unless http && binary
      @http_port, @port = http[1].to_i, binary[1].to_i
      raise 'owner port allocated' if [@http_port, @port].include?(8000)
      tls = Yamora::TLS.new(ca_pem: pem.fetch('ca.pem'), certificate_pem: pem.fetch('client.pem'), private_key_pem: pem.fetch('client.key'))
      @http = Yamora::Client.new(port: @http_port, read_token: READ_TOKEN, write_token: WRITE_TOKEN, tls: tls, timeout: 30)
    rescue Exception
      close
      raise
    end

    def client(**options) = Yamora::BinaryClient.new(binary_config(port, pem, **options))

    def close
      failure = nil
      if @pid
        pid, @pid = @pid, nil
        begin
          observed, status = Process.wait2(pid, Process::WNOHANG)
          unless observed
            Process.kill('TERM', pid)
            _, status = Timeout.timeout(10) { Process.wait2(pid) }
          end
          failure = "native daemon abnormal exit: #{status}" unless status.success?
        rescue Timeout::Error
          Process.kill('KILL', pid)
          Process.wait(pid)
          failure = 'native daemon required forced shutdown'
        ensure
          @reader&.close unless @reader&.closed?
        end
      end
      diagnostics = File.file?(@log_path.to_s) ? File.read(@log_path) : ''
      failure = "native sanitizer failure: #{diagnostics}" if diagnostics.match?(/Sanitizer|runtime error:/)
      failure ||= 'immutable native daemon changed' if @binary && Digest::SHA256.file(@binary).hexdigest != @digest
      raise failure if failure
    end

    private

    def native_environment
      { 'ASAN_OPTIONS' => 'detect_leaks=1:abort_on_error=1:halt_on_error=1', 'UBSAN_OPTIONS' => 'halt_on_error=1:print_stacktrace=1' }
    end

    def command(*args)
      log_path = File.join(@root, 'init.log')
      pid = Process.spawn(native_environment, *args, out: log_path, err: log_path)
      begin
        _, status = Timeout.timeout(20) { Process.wait2(pid) }
        diagnostics = File.read(log_path)
        raise "native fixture command failed: #{diagnostics}" unless status.success? && !diagnostics.match?(/Sanitizer|runtime error:/)
      ensure
        stop_owned(pid)
      end
    end

    def write(name, contents)
      File.write(File.join(@root, name), contents, mode: 'w', perm: 0o600)
    end

    # Fresh synthetic fixture only: emulate the frozen 256 KiB store profile.
    def legacy_image(path)
      image = File.binread(path)
      [0, 4096].each do |base|
        image[base, 8] = 'YAMDIS04'
        crc = 0xffffffff
        image.byteslice(base, 4092).each_byte do |byte|
          crc ^= byte
          8.times { crc = (crc >> 1) ^ (crc.odd? ? 0x82f63b78 : 0) }
        end
        image[base + 4092, 4] = [(~crc) & 0xffffffff].pack('V')
      end
      File.binwrite(path, image)
    end
  end

  def native_test(cert_options: {}, **options)
    scratch do |dir|
      pem = certificates(dir, **cert_options)
      daemon = NativeBinary.new(dir, pem, **options)
      begin
        yield daemon
      ensure
        daemon.close
      end
    end
  end

  def native_rejection(status)
    error = assert_raises(Yamora::BinaryStatusError) { yield }
    assert_equal status, error.status
    refute error.uncertain?
  end
end
