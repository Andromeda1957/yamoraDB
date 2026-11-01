# frozen_string_literal: true

require_relative 'helper'

class TransportTest < Minitest::Test
  include DriverFixtures

  def test_replication_source_guard_is_typed_and_never_writes
    [false, nil, 'false', 'true', 0, 1, [], {}, true, :absent, :nested].each do |value|
      fields = case value
               when :absent then {}
               when :nested then { 'nested' => { 'replication_policy_free' => false } }
               else { 'replication_policy_free' => value }
               end
      readiness = { 'revision' => REV }.merge(fields)
      with_peer(->(socket, _) { socket.write(reply(JSON.generate(readiness))) }) do |client, peer|
        if value == true || value == :absent || value == :nested
          assert_equal readiness, client.require_replication_source
        else
          error = assert_raises(value.equal?(false) ? Yamora::SchemaPolicyReplicationError : Yamora::ProtocolError) do
            client.require_replication_source
          end
          refute error.uncertain?
          assert_equal 409, error.status if value.equal?(false)
        end
        assert_equal ['GET /readyz HTTP/1.1'], peer.requests.map(&:first)
      end
    end
  end

  def test_invalid_configuration_and_redacted_inspection
    bad_hosts = ['localhost', 'example.com', '8.8.8.8', '0.0.0.0', '169.254.169.254', '::1', '[::1]',
                 '127.1', '0177.0.0.1', '127.0.0.01', '127.0.0.256', '2130706433', '127.0.0.1/path',
                 'http://127.0.0.1', '127.0.0.1:8091', "127.0.0.1\n", '127.0.0.1@10.0.0.1', nil]
    bad_hosts.each { |host| assert_raises(ArgumentError) { Yamora::Client.new(host: host) } }
    %w[127.0.0.2 10.0.0.1 172.16.0.1 172.31.255.254 192.168.0.1].each do |host|
      assert_instance_of Yamora::Client, Yamora::Client.new(host: host)
    end
    [0, 65_536, -1, '8091', 1.5, nil, true].each { |port| assert_raises(ArgumentError) { Yamora::Client.new(port: port) } }
    [0, -1, 31, Float::NAN, Float::INFINITY, true, nil, '5'].each { |timeout| assert_raises(ArgumentError) { Yamora::Client.new(timeout: timeout) } }
    ['', 'r' * 31, 'r' * 513, 'r' * 31 + ' ', 'r' * 31 + "\n", 'r' * 31 + "\x7f", 'r' * 31 + 'é'].each do |token|
      %i[read_token write_token].each { |key| assert_raises(ArgumentError) { Yamora::Client.new(**{ key => token }) } }
    end
    assert_raises(ArgumentError) { Yamora::Client.new(tls: OpenSSL::SSL::SSLContext.new) }
    assert_raises(ArgumentError) { Yamora::TLS.new(ca_pem: 'garbage') }
    assert_raises(ArgumentError) { Yamora::TLS.new(certificate_pem: 'garbage') }
    refute_includes Yamora::Client.new(read_token: READ_TOKEN).inspect, READ_TOKEN
    refute_includes Yamora::TLS.new.inspect, 'PRIVATE KEY'
  end

  def test_invalid_paths_conditions_and_structured_values_fail_before_network
    client = Yamora::Client.new(port: 1)
    ['../people', '/people', 'People', 'people%2fdata', "people\n", '', 'a' * 129].each do |id|
      assert_raises(ArgumentError) { client.get(id, 'a') }
      assert_raises(ArgumentError) { client.get('people', id) }
    end
    assert_raises(ArgumentError) { client.put('p', 'a', "x: 1\n", etag: ETAG, create_only: true) }
    [ETAG.upcase, %Q("#{ETAG}"), "#{ETAG}\r\nX: y", 'bad'].each do |etag|
      assert_raises(ArgumentError) { client.delete('p', 'a', etag: etag) }
    end
    ['', "x: \xff\n".b, 'x' * (Yamora::MAX_DOCUMENT_BYTES + 1)].each do |source|
      assert_raises(ArgumentError) { client.put('p', 'a', source) }
    end
    assert_raises(ArgumentError) { client.query('p', { 'after' => 'a' }) }
    assert_raises(ArgumentError) { client.query('p', { 'limit' => true }) }
    assert_raises(ArgumentError) { client.query('p', { 'sort' => { 'x' => 0 } }) }
    assert_raises(ArgumentError) { client.query('p', { 'filter' => { 'blob' => 'x' * (2 * 1024 * 1024) } }) }
    assert_raises(ArgumentError) { client.patch('p', 'a', { '$set' => { 'x' => Float::NAN } }) }
    assert_raises(ArgumentError) { client.patch('p', 'a', { '$set' => { 'x' => "\xff".b } }) }
    assert_raises(ArgumentError) { client.patch('p', 'a', { '$set' => { 'x' => Object.new } }) }
    assert_raises(ArgumentError) { client.patch('p', 'a', { '$set' => { 'x' => 2**64 } }) }
    cycle = []; cycle << cycle
    assert_raises(ArgumentError) { client.patch('p', 'a', { '$set' => { 'x' => cycle } }) }
    assert_raises(ArgumentError) { client.transaction([{ 'collection' => 'p', 'document' => 'a', 'put' => 'x: 1', 'delete' => true }]) }
    op = { 'collection' => 'p', 'document' => 'a', 'delete' => true }
    assert_raises(ArgumentError) { client.transaction([op, op]) }
    assert_raises(ArgumentError) { client.set_indexes([{ 'collection' => 'p', 'name' => 'x', 'fields' => [] }]) }
    assert_raises(ArgumentError) { client.changes(after: '../bad') }
  end

  def test_authentication_exact_source_and_no_environment_proxy
    source = "# Authored café\r\nname: 'Ada'  # keep\r\nvalue: 9223372036854775807\r\n"
    handler = lambda do |socket, (line, headers, body)|
      assert_equal 'close', headers['connection']
      assert_equal 'identity', headers['accept-encoding']
      if line.start_with?('PUT ')
        assert_equal "Bearer #{WRITE_TOKEN}", headers['authorization']
        assert_equal '*', headers['if-none-match']
        assert_equal 'application/yaml', headers['content-type']
        assert_equal source.b, body
        value = { status: 'stored', collection: 'people', document: 'ada', etag: ETAG, revision: REV }
        socket.write(reply(JSON.generate(value), status: 201))
      else
        assert_equal "Bearer #{READ_TOKEN}", headers['authorization']
        socket.write(reply(source, headers: { 'Content-Type' => 'application/yaml', 'ETag' => %Q("#{ETAG}") }))
      end
    end
    previous = ENV.to_h.slice('http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'no_proxy', 'NO_PROXY')
    proxy = Peer.new { |_socket, _request| flunk 'environment proxy contacted' }
    begin
      %w[http_proxy HTTP_PROXY https_proxy HTTPS_PROXY].each { |key| ENV[key] = "http://127.0.0.1:#{proxy.port}" }
      ENV['no_proxy'] = ENV['NO_PROXY'] = ''
      with_peer(handler) do |client, peer|
        assert_equal ETAG, client.put('people', 'ada', source, create_only: true)['etag']
        assert_equal source.b, client.get('people', 'ada').source.b
        assert_equal 2, peer.requests.size
      end
      assert_empty proxy.requests
    ensure
      %w[http_proxy HTTP_PROXY https_proxy HTTPS_PROXY no_proxy NO_PROXY].each { |key| ENV.delete(key) }
      previous.each { |key, value| ENV[key] = value }
      proxy.close
    end
  end

  def test_redirects_never_forward_credentials_or_replay_mutations
    target = Peer.new { |_socket, _request| flunk 'redirect followed' }
    begin
      [301, 302, 303, 307, 308].each do |status|
        handler = ->(socket, _) { socket.write(reply('', status: status, headers: { 'Location' => "http://127.0.0.1:#{target.port}/" })) }
        with_peer(handler) do |client, peer|
          error = assert_raises(Yamora::HTTPError) { client.put('people', 'ada', "name: Ada\n") }
          assert_equal status, error.status
          assert error.uncertain?
          assert_equal 1, peer.requests.size
        end
      end
      assert_empty target.requests
    ensure
      target.close
    end
  end

  def test_proxy_settings_are_not_consulted_even_before_loopback_bypass
    original_lookup = ENV.method(:[])
    reject_proxy = method(:flunk)
    lookup = lambda do |key|
      reject_proxy.call('proxy environment consulted') if %w[http_proxy HTTP_PROXY https_proxy HTTPS_PROXY no_proxy NO_PROXY].include?(key)
      original_lookup.call(key)
    end
    with_peer(->(socket, _) { socket.write(reply) }) do |client, peer|
      # URI's environment proxy discovery itself normally bypasses loopback.
      # Observe that boundary as well as the real socket destination, so the
      # test also rejects :ENV on hosts where a loopback proxy seems harmless.
      begin
        ENV.define_singleton_method(:[], lookup)
        assert_equal REV, client.health['revision']
      ensure
        ENV.define_singleton_method(:[], original_lookup)
      end
      assert_equal 1, peer.requests.size
    end
  end

  def test_lost_reply_never_retries_put_delete_or_get
    with_peer(->(_socket, _) {}) do |client, peer|
      error = assert_raises(Yamora::TransportError) { client.put('p', 'a', "x: 1\n") }
      assert error.uncertain?
      assert_nil error.cause
      assert_equal 1, peer.requests.size
      assert_raises(Yamora::TransportError) { client.delete('p', 'a') }
      assert_equal 2, peer.requests.size
      error = assert_raises(Yamora::TransportError) { client.health }
      refute error.uncertain?
      assert_equal 3, peer.requests.size
    end
  end

  def test_conditional_and_remote_errors_are_redacted_and_not_retried
    [401, 403, 404, 409, 412, 500, 503].each do |status|
      with_peer(->(socket, _) { socket.write(reply(WRITE_TOKEN, status: status)) }) do |client, peer|
        error = assert_raises(Yamora::HTTPError) { client.patch('p', 'a', { '$inc' => { 'n' => 1 } }, etag: ETAG) }
        assert_equal status, error.status
        assert_equal status >= 500, error.uncertain?
        assert_equal %Q("#{ETAG}"), peer.requests.first[1]['if-match']
        refute_includes error.full_message, WRITE_TOKEN
        assert_equal 1, peer.requests.size
      end
    end
  end

  def test_truncation_oversize_and_unexpected_framing
    replies = [
      reply('{}', headers: { 'Content-Length' => '20' }),
      reply('{}', headers: { 'Content-Length' => '999999999' }),
      reply('{}', headers: { 'Content-Length' => '-1' }),
      reply('{}', headers: { 'Content-Length' => '1, 1' }),
      reply('{}', headers: { 'Content-Length' => "2\r\nContent-Length: 2" }),
      reply('{}', headers: { 'Content-Encoding' => 'gzip' }),
      reply("2\r\n{}\r\n0\r\n\r\n", headers: { 'Transfer-Encoding' => 'chunked' }),
      reply('{}').sub("Content-Length: 2\r\n", ''),
      reply('x' * 33),
      "HTTP/1.1 200 Test\r\nLarge: #{'a' * 17_000}\r\n\r\n",
      "HTTP/1.1 200 Test\r\n#{(1..67).map { |n| "X-#{n}: v\r\n" }.join}\r\n",
      reply('{}', headers: { 'X-YamlDB-Revision' => "#{REV}\r\n folded" })
    ]
    replies.each do |wire|
      with_peer(->(socket, _) { socket.write(wire) }, max_response_bytes: 32) do |client, peer|
        assert_raises(Yamora::Error) { client.health }
        assert_equal 1, peer.requests.size
      end
    end
  end

  def test_socket_and_absolute_deadlines
    %i[stall header_drip body_drip].each do |mode|
      handler = lambda do |socket, _|
        if mode == :body_drip
          payload = JSON.generate('pad' => 'x' * 40)
          socket.write(reply(payload).delete_suffix(payload))
          payload.each_byte { |byte| sleep 0.02; socket.write(byte.chr) }
        else
          socket.write("HTTP/1.1 200 Test\r\nContent-Length: 2\r\n")
          40.times { sleep 0.02; socket.write('X') } if mode == :header_drip
          sleep 0.15 if mode == :stall
        end
      rescue Errno::EPIPE, Errno::ECONNRESET
        nil
      end
      with_peer(handler, timeout: 0.1) do |client, _|
        before = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        assert_raises(Yamora::TransportError) { client.health }
        assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - before, :<, 0.5
      end
    end
  end

  def test_byte_cap_rejects_valid_json_before_body_read
    bodies = [reply(JSON.generate('pad' => 'x' * 40)), reply('{}', headers: { 'Content-Length' => '33' })]
    bodies.each do |wire|
      with_peer(->(socket, _) { socket.write(wire) }, max_response_bytes: 32) do |client, _|
        assert_raises(Yamora::LimitError) { client.health }
      end
    end
  end

  def test_invalid_metadata_json_and_mutation_receipts
    [reply('[]'), reply('{bad'), reply('{"status":"ok","status":"bad"}'), reply("{\"x\":\"\xff\"}".b), reply('{}', headers: { 'Content-Type' => 'text/html' }),
     reply('{}', headers: { 'X-YamlDB-Revision' => 'bad' }), reply(JSON.generate('revision' => 'f' * 16)),
     reply('[' * 65 + '0' + ']' * 65)].each do |wire|
      with_peer(->(socket, _) { socket.write(wire) }) { |client, _| assert_raises(Yamora::ProtocolError) { client.health } }
    end
    with_peer(->(socket, _) { socket.write(reply('{}')) }) do |client, _|
      error = assert_raises(Yamora::ProtocolError) { client.put('p', 'a', 'x: 1') }
      assert error.uncertain?
    end
  end

  def test_pagination_detects_changed_revision_and_invalid_progress
    calls = 0
    handler = lambda do |socket, _|
      calls += 1
      body = { 'collection' => 'p', 'documents' => [calls == 1 ? 'a' : 'b'], 'next_after' => calls == 1 ? 'a' : nil }
      socket.write(reply(JSON.generate(body), headers: { 'X-YamlDB-Revision' => calls == 1 ? REV : 'f' * 16 }))
    end
    with_peer(handler) do |client, _|
      visited = []
      assert_raises(Yamora::RevisionError) { client.each_document('p', limit: 1) { |id| visited << id } }
      assert_equal ['a'], visited
    end
    [{ documents: ['b', 'a'], next_after: 'a' }, { documents: ['a'], next_after: 'b' }, { documents: [], next_after: 'a' }].each do |page|
      with_peer(->(socket, _) { socket.write(reply(JSON.generate(page.merge(collection: 'p')))) }) do |client, _|
        assert_raises(Yamora::ProtocolError) { client.document_page('p') }
      end
    end
  end
end
