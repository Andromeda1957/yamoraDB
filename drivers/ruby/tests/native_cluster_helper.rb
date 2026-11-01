# frozen_string_literal: true

require_relative 'cluster_helper'

module NativeClusterFixtures
  include ClusterFixtures

  class NativeCluster
    include ClusterFixtures
    attr_reader :seeds, :tls, :pem, :root, :binary

    def initialize(root)
      @root = root
      @binary = ENV.fetch('YAMORA_TEST_BINARY') { raise 'YAMORA_TEST_BINARY is required for cluster acceptance' }
      raise 'absolute executable native daemon required' unless binary.start_with?('/') && File.executable?(binary)
      @nodes, @reservations = [], []
      prepare_certificates
      @tls = Yamora::TLS.new(ca_pem: @pem['ca.pem'], certificate_pem: @pem['client.pem'], private_key_pem: @pem['client.key'])
      peers = 3.times.map { |i| { id: i + 1, name: "node#{i + 1}.test", address: '127.0.0.1', port: reserve } }
      @seeds = 3.times.map { |i| { host: '127.0.0.1', port: reserve, node: i + 1 } }
      write('read.token', READ_TOKEN); write('write.token', WRITE_TOKEN)
      3.times do |i|
        data, journal = path("data#{i}"), path("journal#{i}")
        Dir.mkdir(data, 0o700); Dir.mkdir(journal, 0o700)
        spec = { cluster: CLUSTER, node: i + 1, journal_dir: journal, peers: peers,
                 peer_tls: { cert_file: path("node#{i + 1}.pem"), key_file: path("node#{i + 1}.key"), ca_file: path('ca.pem') },
                 request_timeout_ms: 3000, journal_cache_bytes: 1_048_576 }
        write("config#{i}.json", JSON.generate(spec))
        args = ['--data-dir', data, '--port', seeds[i][:port].to_s, '--workers', '4',
                '--cluster-config-file', path("config#{i}.json"), '--auth-token-file', path('read.token'),
                '--write-auth-token-file', path('write.token'), '--cache-bytes', '1048576',
                '--tls-cert-file', path('server.pem'), '--tls-key-file', path('server.key'),
                '--tls-client-ca-file', path('ca.pem'), '--io-timeout-ms', '3000']
        @nodes << { args: args, pid: nil, log: path("node#{i}.log") }
      end
      @reservations.each(&:close); @reservations.clear
      3.times { |i| start(i) }
      leader
    rescue Exception
      close
      raise
    end

    def options
      { seeds: seeds, cluster_id: CLUSTER, voters: 3, tls: tls, read_token: READ_TOKEN, write_token: WRITE_TOKEN,
        timeout: 20, attempt_timeout: 4 }
    end

    def client(**extra) = Yamora::ClusterClient.new(**options, **extra)

    def endpoint(index, timeout: 1)
      Yamora::Client.new(host: seeds[index][:host], port: seeds[index][:port], tls: tls,
                         read_token: READ_TOKEN, write_token: WRITE_TOKEN, timeout: timeout).instance_variable_get(:@transport)
    end

    def leader
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 15
      observations = {}
      loop do
        @nodes.each_with_index do |node, index|
          next unless node[:pid]
          begin
            body, = endpoint(index, timeout: 0.3).request('GET', '/v1/cluster/status')
            observations[index] = JSON.parse(body)
            return index if observations[index]['role'] == 'leader'
          rescue Yamora::Error => error
            observations[index] = [error.class.name, error.status, error.message]
          end
        end
        raise "native leader election timed out: #{observations}; #{@nodes.map { |node| File.read(node[:log]) }}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
        sleep 0.025
      end
    end

    def start(index)
      node = @nodes[index]
      raise 'already started' if node[:pid]
      reader, writer = IO.pipe
      log = File.open(node[:log], 'a+')
      begin
        node[:pid] = Process.spawn(binary, *node[:args], out: writer, err: log)
        writer.close
        banner = Timeout.timeout(15) { reader.gets }
        raise "native startup failed: #{banner.inspect}; #{File.read(node[:log])}" unless banner&.start_with?("yamora listening on 127.0.0.1:#{seeds[index][:port]} ")
      ensure
        reader.close; writer.close unless writer.closed?; log.close
      end
    end

    def stop(index, crash: false)
      node = @nodes[index]
      return unless node[:pid]
      pid = node[:pid]
      Process.kill(crash ? 'KILL' : 'TERM', pid)
      begin
        _, status = Timeout.timeout(6) { Process.wait2(pid) }
      rescue Timeout::Error
        Process.kill('KILL', pid)
        Process.wait(pid)
        raise 'native member did not stop cleanly'
      ensure
        node[:pid] = nil
      end
      diagnostics = File.read(node[:log])
      valid = crash ? status.signaled? && status.termsig == Signal.list['KILL'] : status.success?
      raise "native member failed: #{status}; #{diagnostics}" unless valid && !diagnostics.match?(/AddressSanitizer|LeakSanitizer|runtime error:/)
    end

    def close
      @reservations&.each(&:close)
      failures = []
      @nodes&.each_index do |index|
        begin
          stop(index)
        rescue StandardError => error
          failures << error
        end
      end
      raise failures.first unless failures.empty?
    end

    private

    def path(name) = File.join(root, name)
    def write(name, content) = File.write(path(name), content, mode: 'w', perm: 0o600)

    def reserve
      socket = TCPServer.new('127.0.0.1', 0)
      port = socket.addr[1]
      raise 'owner port allocated' if port == 8000
      @reservations << socket
      port
    end

    def prepare_certificates
      ca_key = OpenSSL::PKey::EC.generate('prime256v1')
      ca = issue_certificate('CA', ca_key, nil, nil, 1, ca: true)
      @pem = { 'ca.pem' => ca.to_pem }
      [['server', false, 'IP:127.0.0.1'], ['client', true, nil],
       ['node1', false, 'DNS:node1.test,IP:127.0.0.1'], ['node2', false, 'DNS:node2.test,IP:127.0.0.1'],
       ['node3', false, 'DNS:node3.test,IP:127.0.0.1']].each_with_index do |(name, client, san), index|
        key = OpenSSL::PKey::EC.generate('prime256v1')
        cert = issue_certificate(name, key, ca, ca_key, index + 2, client: client, san: san)
        if name.start_with?('node')
          cert.extensions = cert.extensions.reject { |extension| extension.oid == 'extendedKeyUsage' }
          factory = OpenSSL::X509::ExtensionFactory.new
          factory.subject_certificate, factory.issuer_certificate = cert, ca
          cert.add_extension(factory.create_extension('extendedKeyUsage', 'serverAuth,clientAuth'))
          cert.sign(ca_key, OpenSSL::Digest.new('SHA256'))
        end
        @pem["#{name}.pem"], @pem["#{name}.key"] = cert.to_pem, key.to_pem
      end
      @pem.each { |name, content| write(name, content) }
    end
  end

  def with_native_cluster
    scratch do |dir|
      cluster = NativeCluster.new(dir)
      begin
        yield cluster
      ensure
        cluster.close
      end
    end
  end
end
