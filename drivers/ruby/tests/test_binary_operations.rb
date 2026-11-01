# frozen_string_literal: true
require_relative 'binary_helper'

class BinaryOperationsTest < Minitest::Test
  include BinaryFixtures

  def v2_response(socket, fields, body, mode: 0, change: {})
    values = { 1 => [200].pack('n'), 2 => mode == 1 ? 'application/x-ndjson' : 'application/json',
               3 => [mode == 1 ? 0 : body.bytesize].pack('Q>'), 4 => [mode == 1 ? 0 : body.bytesize].pack('Q>'), 5 => REV,
               12 => fields.fetch(8), 13 => [mode].pack('C') }.merge(change).compact
    metadata = bin_fields(values); metadata.setbyte(1, 2)
    socket.write(bin_frame(3, 1, metadata) + (body.empty? ? '' : bin_frame(4, 1, body)) + bin_frame(5, 1))
  end

  def raw_peer(handler, minimum: 1)
    peer_test(->(socket, _owner) do
      _, _, hello = bin_read(socket)
      raise 'missing schema2 negotiation' unless hello.unpack('nn')[1] == 2
      socket.write(bin_frame(1, 0, [minimum, 2, 4096, 1].pack('nnNN')))
      _, _, metadata = bin_read(socket)
      raise 'request schema changed' unless metadata.unpack1('n') == 2
      metadata.setbyte(1, 1)
      fields, source = parse_fields(metadata), +''.b
      loop do
        kind, _, body = bin_read(socket)
        break if kind == 5
        raise 'unexpected request frame' unless kind == 4
        source << body
      end
      handler.call(socket, fields, source)
    end, peer_options: { raw: true }) { |client, peer, pem| yield client, peer, pem }
  end

  def test_protocol_two_only_peer_has_a_common_advertised_range
    response = '{"revision":"0123456789abcdef"}'
    raw_peer(->(socket, fields, _source) { v2_response(socket, fields, response) }, minimum: 2) do |client, _peer|
      result = client.operation('POST', '/v1/query/a', 'application/json', '{}', request_id: ID)
      assert_equal response, result.body
    end
  end

  def test_legacy_peer_fails_typed_before_mutation_request
    peer_test(->(socket, _owner) do
      bin_read(socket)
      socket.write(bin_frame(1, 0, [1, 1, 4096, 1].pack('nnNN')))
      assert_nil socket.read(1), 'unsupported peer received REQUEST'
    end, peer_options: { raw: true }) do |client, _peer|
      error = assert_raises(Yamora::BinaryError) { client.operation('PATCH', '/v1/collections/a/documents/b', 'application/json', '{}') }
      assert_equal :unsupported, error.kind
      refute error.is_a?(Yamora::BinaryUncertainWriteError)
    end
  end

  def test_raw_query_preserves_wide_integer_source_and_response
    source = '{"filter":{"wide":18446744073709551615}}'
    response = '{"revision":"0123456789abcdef","documents":[{"wide":18446744073709551615}]}'
    raw_peer(->(socket, fields, actual) do
      assert_equal source, actual
      assert_equal 'Bearer read-synthetic', fields[5]
      v2_response(socket, fields, response)
    end) do |client, _peer|
      result = client.operation('POST', '/v1/query/a', 'application/json', source, token: 'read-synthetic', request_id: ID)
      assert_equal response, result.body
      assert result.body.frozen?
    end
  end

  def test_response_depth_is_distinct_from_domain_and_bounded
    mapping = '{"deep":' + '{"n":' * 63 + '{}' + '}' * 64
    values = ['{"value":' + '[' * 64 + '0' + ']' * 64 + '}', mapping, '{"edge":[' + mapping + ']}']
    values.each do |value|
      body = '{"revision":"' + REV + '","documents":[' + value + ']}'
      raw_peer(->(socket, fields, _source) { v2_response(socket, fields, body) }) do |client, _peer|
        failure = nil
        begin
          result = client.operation('POST', '/v1/query/a', 'application/json', '{}', request_id: ID)
        rescue Yamora::BinaryError => error
          failure = error.kind
        end
        assert_nil failure, 'native domain edge response was rejected'
        assert_equal body, result.body
      end
    end
    invalid = ['[' * 80 + '0' + ']' * 80, '1,"v":2', '"' + 255.chr + '"']
    invalid.each do |value|
      body = '{"revision":"' + REV + '","v":' + value + '}'
      raw_peer(->(socket, fields, _source) { v2_response(socket, fields, body) }) do |client, _peer|
        error = assert_raises(Yamora::BinaryError) { client.operation('POST', '/v1/query/a', 'application/json', '{}', request_id: ID) }
        assert_equal :protocol, error.kind
      end
    end
    source = '{"operations":[{}],"v":' + '[' * 64 + '0' + ']' * 64 + '}'
    receipt = '{"status":"committed","operations":1,"revision":"' + REV + '"}'
    raw_peer(->(socket, fields, _source) { v2_response(socket, fields, receipt) }) do |client, _peer|
      error = assert_raises(Yamora::BinaryUncertainWriteError) { client.operation('POST', '/v1/transactions', 'application/json', source, request_id: ID) }
      assert_equal :protocol, error.kind
    end
  end

  def test_malformed_mode_and_transaction_receipt_preserve_original_envelope
    [nil, 1, 2, 0].each do |mode|
      source = '{"operations":[{"collection":"a","document":"b","delete":true}]}'
      raw_peer(->(socket, fields, _actual) do
        count = mode == 0 ? 2 : 1
        body = JSON.generate('status' => 'committed', 'operations' => count, 'revision' => REV)
        v2_response(socket, fields, body, change: { 13 => mode.nil? ? nil : [mode].pack('C') })
      end) do |client, _peer|
        error = assert_raises(Yamora::BinaryUncertainWriteError) { client.operation('POST', '/v1/transactions', 'application/json', source, request_id: ID, if_match: '') }
        assert_equal source, error.envelope.source
        assert_equal '', error.envelope.if_match
        assert_equal '/v1/transactions', error.envelope.target
      end
    end
  end

  def test_public_raw_operation_rejects_non_operation_target_before_network
    scratch do |root|
      pem = certificates(root)
      peer = BinaryPeer.new(pem) { |_socket, _request, _owner| flunk('invalid target dispatched') }
      client = Yamora::BinaryClient.new(binary_config(peer.port, pem))
      begin
        assert_respond_to client, :operation
        assert_raises(Yamora::BinaryError) { client.operation('POST', '/metrics', 'application/json', '{}') }
        assert_equal [], peer.requests
      ensure
        client.close
        peer.close
      end
    end
  end
end
