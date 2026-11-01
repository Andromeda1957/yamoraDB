# frozen_string_literal: true

require_relative 'binary_native_helper'

class BinaryConfigTest < Minitest::Test
  include BinaryNativeFixtures

  def test_config_rejects_noncanonical_routes_opaque_trust_paths_callbacks_and_limits
    scratch do |dir|
      pem = certificates(dir)
      defaults = { host: '127.0.0.1', port: 7401, server_name: '127.0.0.1', ca_pem: pem['ca.pem'] }
      variants = [{ host: 'localhost' }, { host: '127.000.0.1' }, { host: '8.8.8.8' }, { host: '169.254.1.1' },
                  { host: '192.168.0.256' }, { host: '::1' }, { host: '127.1' }, { host: '127.0.0.1/path' },
                  { port: 0 }, { port: '7401' }, { timeout: 0 }, { timeout: Float::INFINITY }, { timeout: 31 },
                  { concurrency: 0 }, { concurrency: 5 }, { max_frame: 4095 }, { max_frame: 65_537 },
                  { server_name: '' }, { server_name: 'bad/name' }, { server_name: '-bad.test' },
                  { ca_pem: OpenSSL::X509::Store.new }, { ca_pem: File.join(dir, 'ca.pem') },
                  { ca_pem: pem['ca.pem'] + 'unparsed trust material' }, { certificate_pem: pem['client.pem'] },
                  { private_key_pem: pem['client.key'] }, { certificate_pem: pem['client.pem'], private_key_pem: pem['server.key'] }]
      variants.each do |extra|
        error = assert_raises(Yamora::BinaryError) { Yamora::BinaryConfig.new(**defaults, **extra) }
        assert_equal :config, error.kind
        refute error.uncertain?
        assert_nil error.cause
      end
      [{ verify_mode: OpenSSL::SSL::VERIFY_NONE }, { verify_callback: ->(*) { true } }, { tls: OpenSSL::SSL::SSLContext.new }].each do |extra|
        assert_raises(ArgumentError) { Yamora::BinaryConfig.new(**defaults, **extra) }
      end
      source = Object.new
      calls = []
      source.define_singleton_method(:instance_of?) { |_| true }
      source.define_singleton_method(:to_str) { calls << :conversion; SOURCE }
      binary_failure(:input) { Yamora::BinaryEnvelope.new(method: 'PUT', collection: 'c', document: 'd', source: source) }
      assert_empty calls
    end
  end

  def test_required_native_dns_san_identity_routes_only_to_explicit_numeric_destination
    native_test(cert_options: { san: 'DNS:binary.invalid,IP:127.0.0.1', server_name: 'binary.invalid' }) do |daemon|
      identity, host = +'binary.invalid', +'127.0.0.1'
      client = Yamora::BinaryClient.new(binary_config(daemon.port, daemon.pem, host: host, server_name: identity))
      identity.replace('changed.invalid'); host.replace('8.8.8.8')
      assert_equal 201, client.put('c', 'named', SOURCE, token: WRITE_TOKEN).status
      assert_equal SOURCE.b, client.get('c', 'named', token: READ_TOKEN).body.b
      assert_equal SOURCE.b, daemon.http.get('c', 'named').source.b
      assert_equal 'binary.invalid', client.config.server_name
      assert_equal '127.0.0.1', client.config.host
    end
  end

  def test_expired_wrong_san_and_cn_only_tls_peers_fail_before_dispatch
    [{ expired: true }, { san: 'IP:127.0.0.2' }, { san: nil, server_name: '127.0.0.1' }].each do |certificate|
      scratch do |dir|
        pem = certificates(dir, **certificate)
        peer = BinaryPeer.new(pem, handshake_failure: true) { flunk 'unverified peer received a document request' }
        begin
          client = Yamora::BinaryClient.new(binary_config(peer.port, pem))
          error = assert_raises(Yamora::BinaryError) { client.put('c', 'denied', SOURCE, token: WRITE_TOKEN) }
          refute error.uncertain?
          assert_nil error.request_id
          assert_empty peer.requests
        ensure
          peer.close
        end
      end
    end
  end

  def test_cpu_hash_checks_share_the_existing_budget_and_final_deadline
    wire = Yamora.const_get(:BinaryWire)
    checks = 0
    budget = Object.new
    budget.define_singleton_method(:check) do
      checks += 1
      raise Yamora::BinaryError.new(:timeout) if checks == 3
      1
    end
    binary_failure(:timeout) { wire.source_etag('x' * 16_384, budget) }
    assert_equal 3, checks
  end
end
