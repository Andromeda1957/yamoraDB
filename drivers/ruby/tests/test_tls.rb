# frozen_string_literal: true

require_relative 'helper'

class TLSTest < Minitest::Test
  include DriverFixtures

  def test_stalled_tls_deadline_closes_unpublished_socket_without_gc
    listener = TCPServer.new('127.0.0.1', 0)
    port = listener.addr[1]
    raise 'owner port allocated' if port == 8000
    client = Yamora::Client.new(port: port, tls: Yamora::TLS.new, timeout: 0.1)
    # Start the timeout scheduler before measuring descriptors. No SSL server
    # runs: TCP accepts the ClientHello, then deliberately stalls the handshake.
    begin
      Timeout.timeout(0.001, Timeout::Error) { sleep 0.01 }
    rescue Timeout::Error
      nil
    end
    GC.start
    previously_disabled = GC.disable
    baseline = Dir.children('/proc/self/fd').size if Dir.exist?('/proc/self/fd')
    3.times do
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      error = assert_raises(Yamora::TransportError) { client.health }
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
      assert_operator elapsed, :>=, 0.05
      assert_operator elapsed, :<, 0.5
      refute error.uncertain?
      socket = listener.accept_nonblock
      begin
        hello = Timeout.timeout(0.2, Timeout::Error) { socket.read }
        closed = true
      rescue Timeout::Error
        closed = false
      ensure
        socket.close
      end
      assert_equal baseline, Dir.children('/proc/self/fd').size, 'TLS deadline leaked a client descriptor while GC was disabled' if baseline
      assert closed, 'TLS deadline left the peer connected until garbage collection'
      refute_empty hello, 'TLS handshake never sent a ClientHello'
    end
    assert_raises(IO::WaitReadable) { listener.accept_nonblock }
  ensure
    listener&.close
    unless previously_disabled
      GC.enable
      GC.start
    end
  end

  def with_tls_peer(pem, version: OpenSSL::SSL::TLS1_3_VERSION, requests: nil, closed: nil)
    tcp = TCPServer.new('127.0.0.1', 0)
    context = OpenSSL::SSL::SSLContext.new
    context.min_version = context.max_version = version
    context.cert = OpenSSL::X509::Certificate.new(pem['server.pem'])
    context.key = OpenSSL::PKey.read(pem['server.key'])
    server = OpenSSL::SSL::SSLServer.new(tcp, context)
    negotiated = Queue.new
    thread = Thread.new do
      connection = nil
      begin
        Timeout.timeout(3) do
          connection = server.accept
          negotiated << connection.ssl_version
          first = connection.gets
          if first
            headers = +first
            loop do
              line = connection.gets
              break if line.nil? || line == "\r\n"
              headers << line
            end
            requests << headers if requests
            connection.write(reply)
          else
            closed << true if closed
          end
        end
      rescue OpenSSL::SSL::SSLError, IOError, SystemCallError, Timeout::Error
        nil
      ensure
        connection&.close
      end
    end
    thread.report_on_exception = false
    yield tcp.addr[1], negotiated
  ensure
    tcp&.close
    thread&.join(4) || thread&.kill&.join
  end

  def test_real_tls_rejects_expired_server_and_tls12_downgrade
    scratch do |dir|
      expired = certificates(dir, expired: true)
      tls = Yamora::TLS.new(ca_pem: expired['ca.pem'])
      with_tls_peer(expired) do |port, negotiated|
        assert_raises(Yamora::TransportError) { Yamora::Client.new(port: port, tls: tls).health }
        assert negotiated.empty?
      end
    end
    scratch do |dir|
      pem = certificates(dir)
      tls = Yamora::TLS.new(ca_pem: pem['ca.pem'])
      with_tls_peer(pem) do |port, negotiated|
        assert_equal REV, Yamora::Client.new(port: port, tls: tls).health['revision']
        assert_equal 'TLSv1.3', negotiated.pop
      end
      with_tls_peer(pem, version: OpenSSL::SSL::TLS1_2_VERSION) do |port, negotiated|
        assert_raises(Yamora::TransportError) { Yamora::Client.new(port: port, tls: tls).health }
        assert negotiated.empty?
      end
    end
  end

  def assert_rejected_ip_identity(san:, server_name: 'server')
    scratch do |dir|
      pem = certificates(dir, san: san, server_name: server_name)
      store = OpenSSL::X509::Store.new
      store.add_cert(OpenSSL::X509::Certificate.new(pem['ca.pem']))
      assert store.verify(OpenSSL::X509::Certificate.new(pem['server.pem'])), 'fixture chain must be trusted'
      tls = Yamora::TLS.new(ca_pem: pem['ca.pem'])
      %i[read write].each do |operation|
        requests, closed = [], Queue.new
        previously_disabled = GC.disable
        begin
          with_tls_peer(pem, requests: requests, closed: closed) do |port, _|
            client = Yamora::Client.new(port: port, tls: tls, read_token: READ_TOKEN, write_token: WRITE_TOKEN)
            error = assert_raises(Yamora::TransportError) do
              operation == :read ? client.health : client.put('p', 'a', "secret: payload\n")
            end
            assert_equal operation == :write, error.uncertain?
          end
          assert_empty requests, 'IP identity rejection must precede all HTTP credentials and bytes'
          assert closed.pop(true), 'IP identity rejection must close its TLS socket without GC'
        ensure
          GC.enable unless previously_disabled
        end
      end
    end
  end

  def test_tls_rejects_numeric_dns_san_before_credentials
    assert_rejected_ip_identity(san: 'DNS:127.0.0.1')
  end

  def test_tls_rejects_wildcard_dns_san_before_credentials
    assert_rejected_ip_identity(san: 'DNS:*.0.0.1')
  end

  def test_tls_rejects_numeric_common_name_without_ip_san
    assert_rejected_ip_identity(san: nil, server_name: '127.0.0.1')
  end

  def test_tls_rejects_matching_dns_san_with_wrong_ip_san
    assert_rejected_ip_identity(san: 'DNS:127.0.0.1,IP:127.0.0.2')
  end

  def test_tls_accepts_matching_ip_san_among_other_identities
    scratch do |dir|
      pem = certificates(dir, san: 'DNS:unrelated.example,IP:127.0.0.2,IP:127.0.0.1')
      with_tls_peer(pem) do |port, _|
        tls = Yamora::TLS.new(ca_pem: pem['ca.pem'])
        assert_equal REV, Yamora::Client.new(port: port, tls: tls).health['revision']
      end
    end
  end

  def test_key_mismatch_and_encrypted_key_fail_without_prompting
    scratch do |dir|
      pem = certificates(dir)
      assert_raises(ArgumentError) { Yamora::TLS.new(certificate_pem: pem['client.pem'], private_key_pem: pem['server.key']) }
      encrypted = OpenSSL::PKey.read(pem['client.key']).export(OpenSSL::Cipher.new('aes-256-cbc'), 'fixture-passphrase')
      Timeout.timeout(1) do
        assert_raises(ArgumentError) { Yamora::TLS.new(certificate_pem: pem['client.pem'], private_key_pem: encrypted) }
      end
    end
  end
end
