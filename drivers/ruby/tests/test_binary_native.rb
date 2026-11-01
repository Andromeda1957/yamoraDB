# frozen_string_literal: true

require_relative 'binary_native_helper'

class BinaryNativeTest < Minitest::Test
  include BinaryNativeFixtures

  def test_required_native_crud_http_byte_interoperability_roles_conditions_and_mtls
    native_test do |daemon|
      client = daemon.client(max_frame: 4096)
      sources = [SOURCE, "# Windows\r\nname: 'Ada'  # exact spacing\r\n", "# Unicode\ntext: 'λ雪é'\nblock: |\n  first\n  second\n"]
      sources.each_with_index do |source, index|
        id = "doc-#{index}"
        created = client.put('c', id, source, token: WRITE_TOKEN, if_none_match: '*', request_id: ID)
        assert_equal 201, created.status
        assert_equal source.b, daemon.http.get('c', id).source.b
        assert_equal native_etag(source), created.etag
        fetched = client.get('c', id, token: READ_TOKEN)
        assert_equal source.b, fetched.body.b
        assert_equal created.etag, fetched.etag
        assert_equal created.revision, fetched.revision
        head = client.head('c', id, token: READ_TOKEN, request_id: ID)
        assert_equal source.bytesize, head.representation_length
        assert_equal ID, head.request_id
        assert_equal fetched.etag, head.etag
        assert_empty head.body
        native_rejection(412) { client.put('c', id, source, token: WRITE_TOKEN, if_none_match: '*') }
        native_rejection(412) { client.put('c', id, source, token: WRITE_TOKEN, if_match: '"0000000000000000"') }
        native_rejection(400) { client.put('c', id, source, token: WRITE_TOKEN, if_match: '') }
        native_rejection(400) { client.put('c', id, source, token: WRITE_TOKEN, if_match: fetched.etag, if_none_match: '*') }
        replaced = client.put('c', id, source, token: WRITE_TOKEN, if_match: fetched.etag)
        assert_equal 200, replaced.status
        replacement = "# HTTP-authored source\r\nv: #{index}\r\n"
        daemon.http.put('c', id, replacement)
        assert_equal replacement.b, client.get('c', id, token: READ_TOKEN).body.b
        native_rejection(412) { client.delete('c', id, token: WRITE_TOKEN, if_match: fetched.etag) }
        current = client.get('c', id, token: READ_TOKEN)
        deleted = client.delete('c', id, token: WRITE_TOKEN, if_match: current.etag)
        assert_equal 204, deleted.status
        assert_empty deleted.body
        assert_equal 0, deleted.representation_length
        native_rejection(404) { client.head('c', id, token: READ_TOKEN) }
        assert_raises(Yamora::HTTPError) { daemon.http.get('c', id) }
      end
      native_rejection(401) { client.get('c', 'd') }
      native_rejection(401) { client.put('c', 'd', SOURCE, token: READ_TOKEN) }
      native_rejection(403) { client.get('c', 'd', token: 's' * 32) }
      assert_equal 201, client.put('allowed', 'd', SOURCE, token: 's' * 32).status
      assert_equal SOURCE.b, client.get('allowed', 'd', token: 's' * 32).body.b
      anonymous = Yamora::BinaryClient.new(binary_config(daemon.port, daemon.pem.merge('client.pem' => nil, 'client.key' => nil)))
      error = assert_raises(Yamora::BinaryError) { anonymous.put('c', 'd', SOURCE, token: WRITE_TOKEN) }
      refute error.uncertain?
      wrong_name = Yamora::BinaryClient.new(binary_config(daemon.port, daemon.pem, server_name: 'wrong.invalid'))
      error = assert_raises(Yamora::BinaryError) { wrong_name.put('c', 'd', SOURCE, token: WRITE_TOKEN) }
      refute error.uncertain?
      wrong_trust = Yamora::BinaryClient.new(binary_config(daemon.port, daemon.pem.merge('ca.pem' => daemon.pem['client.pem'])))
      error = assert_raises(Yamora::BinaryError) { wrong_trust.get('c', 'd', token: READ_TOKEN) }
      refute error.uncertain?
    end
  end

  def test_required_native_16mib_source_over_4kib_frames_and_legacy_rejection
    native_test do |daemon|
      client = daemon.client(max_frame: 4096)
      prefix = "# authored café CRLF\r\nv: 01\r\n# "
      source = prefix + 'x' * (16 * 1024 * 1024 - prefix.bytesize - 2) + "\r\n"
      assert_equal 16 * 1024 * 1024, source.bytesize
      stored = client.put('c', 'large', source, token: WRITE_TOKEN, if_none_match: '*')
      assert_equal 201, stored.status
      assert_equal source.b, daemon.http.get('c', 'large').source.b
      assert_equal source.b, client.get('c', 'large', token: READ_TOKEN).body.b
      assert_equal source.bytesize, client.head('c', 'large', token: READ_TOKEN).representation_length
    end
    native_test(legacy: true) do |daemon|
      client = daemon.client(max_frame: 4096)
      source = "v: 1\n# " + 'x' * (256 * 1024)
      native_rejection(413) { client.put('c', 'legacy', source, token: WRITE_TOKEN) }
      native_rejection(404) { client.get('c', 'legacy', token: READ_TOKEN) }
      assert_raises(Yamora::HTTPError) { daemon.http.get('c', 'legacy') }
    end
  end

  def test_required_native_lost_and_partial_committed_receipts_observe_source_before_explicit_replay
    native_test do |daemon|
      %i[lost partial].each do |mode|
        forwards = []
        peer = BinaryPeer.new(daemon.pem) do |socket, request, _|
          forwards << request
          upstream_socket = TCPSocket.new('127.0.0.1', daemon.port)
          upstream = nil
          begin
            upstream = OpenSSL::SSL::SSLSocket.new(upstream_socket, binary_config(daemon.port, daemon.pem).send(:context))
            upstream.sync_close = true
            upstream.hostname = '127.0.0.1'
            upstream.connect
            upstream.write(bin_frame(1, 0, [1, 1, 4096, 1].pack('nnNN')))
            raise 'native HELLO missing' unless bin_read(upstream).first == 1
            upstream.write(bin_frame(2, 1, bin_fields(request[:fields])))
            request[:source].bytes.each_slice(4096) { |part| upstream.write(bin_frame(4, 1, part.pack('C*'))) }
            upstream.write(bin_frame(5, 1))
            reply_frames = []
            loop do
              frame = bin_read(upstream)
              reply_frames << frame
              break if frame.first == 5
            end
            status = parse_fields(reply_frames.first[2]).fetch(1).unpack1('n')
            if forwards.size == 1
              raise 'native did not commit initial operation' unless status == 201
              socket.write(bin_frame(*reply_frames.first)) if mode == :partial
            else
              reply_frames.each { |frame| socket.write(bin_frame(*frame)) }
            end
          ensure
            upstream&.close
            upstream_socket.close unless upstream_socket.closed?
          end
        end
        begin
          client = Yamora::BinaryClient.new(binary_config(peer.port, daemon.pem))
          mutable = SOURCE.dup
          error = assert_raises(Yamora::BinaryUncertainWriteError) do
            client.put('c', mode.to_s, mutable, token: WRITE_TOKEN, request_id: ID, if_none_match: '*')
          end
          assert_equal 1, forwards.size, 'no implicit binary retry after receipt loss'
          # Independent authoritative HTTP observation MUST precede repetition.
          observed = daemon.http.get('c', mode.to_s)
          assert_equal SOURCE.b, observed.source.b, 'committed source established independently before replay'
          mutable.replace('caller changed source')
          assert_equal SOURCE.b, error.envelope.source
          assert_equal '"' + observed.etag + '"', native_etag(error.envelope.source)
          native_rejection(412) { client.replay(error.envelope, token: WRITE_TOKEN) }
          assert_equal 2, forwards.size, 'all possible binary retries are visible to relay'
          assert_equal forwards.first[:fields].reject { |id, _| [5, 9].include?(id) }, forwards.last[:fields].reject { |id, _| [5, 9].include?(id) }
          assert_equal SOURCE.b, forwards.last[:source]
          assert_equal SOURCE.b, daemon.http.get('c', mode.to_s).source.b
        ensure
          peer.close
        end
      end
    end
  end
end
