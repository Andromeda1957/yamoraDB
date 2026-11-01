# frozen_string_literal: true

require_relative 'binary_helper'

class BinaryWireTest < Minitest::Test
  include BinaryFixtures
  Wire = Yamora.const_get(:BinaryWire)
  Reply = Yamora.const_get(:BinaryReply)
  Budget = Struct.new(:checks) do
    def check = self.checks += 1
  end

  def test_single_stream_client_accepts_bounded_peer_capacity
    [1, 4, 128].each do |streams|
      assert_equal 4096, Wire.negotiate([1, 1, 4096, streams].pack('nnNN'), 65_536)
    end
    [0, 129, 0xffff_ffff].each do |streams|
      binary_failure(:protocol) { Wire.negotiate([1, 1, 4096, streams].pack('nnNN'), 65_536) }
    end
    assert_equal 1, Wire.hello(4096).unpack('nnNN').last
  end

  def test_literal_frame_and_tlv_vectors
    expected = ['594d4246010500000000000100000000'].pack('H*')
    assert_equal expected, Wire.frame(5, 1)
    assert_equal [5, 1, 0], Wire.header(expected, 4096)
    envelope = Yamora::BinaryEnvelope.new(method: 'GET', collection: 'c', document: 'd', request_id: ID)
    encoded = Wire.request(envelope, 'read', 123)
    fields = parse_fields(encoded)
    assert_equal [1].pack('C'), fields[1]
    assert_equal '/v1/collections/c/documents/d', fields[2]
    assert_equal ''.b, fields[3]
    assert_equal [0].pack('Q>'), fields[4]
    assert_equal 'Bearer read', fields[5]
    assert_equal [ID].pack('H*'), fields[8]
    assert_equal [123].pack('N'), fields[9]
    assert_equal 4096, Wire.negotiate([1, 9, 4096, 1].pack('nnNN'), 65_536)
  end

  def test_invalid_header_shapes_reject_before_payload
    vectors = [[1, 1, 12], [2, 1, 4], [3, 1, 2049], [3, 2, 8], [4, 1, 0], [5, 1, 1], [6, 1, 0],
               [7, 1, 3], [8, 1, 8], [9, 0, 7], [10, 0, 1], [11, 1, 0], [4, 3, 10], [4, 1, 4097]]
    vectors.each do |kind, stream, size|
      binary_failure(:protocol) { Wire.header(['YMBF', 1, kind, 0, stream, size].pack('a4CCnNN'), 4096) }
    end
    %w[magic version flags].each do |field|
      header = Wire.frame(5, 1)
      header.setbyte({ 'magic' => 0, 'version' => 4, 'flags' => 7 }.fetch(field), 2)
      binary_failure(:protocol) { Wire.header(header, 4096) }
    end
    [[0, 1, 4096, 1], [2, 3, 4096, 1], [1, 1, 4095, 1], [1, 1, 65_537, 1], [1, 1, 4096, 0], [1, 1, 4096, 129]].each do |hello|
      binary_failure(:protocol) { Wire.negotiate(hello.pack('nnNN'), 65_536) }
    end
  end

  def test_metadata_tlv_order_widths_and_semantic_bounds
    request = { method: 1, fields: { 2 => '/v1/collections/c/documents/d' } }
    fields, = response_parts(request)
    envelope = Yamora::BinaryEnvelope.new(method: 'GET', collection: 'c', document: 'd')
    assert_equal 200, Reply.metadata(bin_fields(fields), envelope)[:status]
    variants = [fields.to_a.reverse.to_h, fields.merge(1 => [200].pack('N')), fields.merge(3 => [16 * 1024 * 1024 + 1].pack('Q>')),
                fields.merge(5 => 'G' * 16), fields.merge(6 => 'a' * 16), fields.merge(7 => 'Wrong'), fields.merge(9 => [1].pack('C')),
                fields.merge(12 => [ID].pack('H*')), fields.reject { |id, _| id == 5 }, fields.merge(13 => 'unknown')]
    variants.each { |variant| binary_failure(:protocol) { Reply.metadata(bin_fields(variant), envelope) } }
    binary_failure(:protocol) { Reply.metadata(bin_fields(fields) + 'tail', envelope) }
    binary_failure(:protocol) { Reply.metadata(bin_fields(fields).byteslice(0...-1), envelope) }
  end

  def test_native_hash_literal_including_unsigned_unicode_octets
    budget = Budget.new(0)
    # Literal values computed from the native engine's persisted/HTTP identity.
    assert_equal '"14650fb0739d0383"', Wire.source_etag(''.b, budget)
    assert_equal native_etag(SOURCE), Wire.source_etag(SOURCE, budget)
    assert_operator budget.checks, :>=, 3
  end

  def test_strict_json_duplicates_depth_nodes_numbers_and_utf8
    budget = Budget.new(0)
    valid = '{"n":18446744073709551615,"s":-9223372036854775808}'
    assert_equal 2**64 - 1, Reply.json(valid, budget)['n']
    invalid = ['{"k":1,"k":2}', '{"n":18446744073709551616}', '{"n":-9223372036854775809}',
               '{"n":1e999}', '{"n":NaN}', '{"n":Infinity}', '[]', '{"n":1} false', "{\"s\":\"\xff\"}".b,
               '{"v":' + '[' * 33 + '0' + ']' * 33 + '}', '{"v":[' + ['0'] * 1024 * ',' + ']}']
    invalid.each { |body| binary_failure(:protocol) { Reply.json(body, budget) } }
  end

  def test_envelopes_own_bytes_without_conversion_hooks_and_redact_source
    source = SOURCE.dup
    def source.to_str = raise('conversion hook called')
    def source.to_json(*) = raise('serialization hook called')
    def source.bytesize = raise('caller method called')
    def source.byteslice(*) = raise('caller method called')
    id = ID.dup
    envelope = Yamora::BinaryEnvelope.new(method: 'PUT', collection: 'c', document: 'd', source: source, request_id: id)
    source.replace('mutated'); id.replace('f' * 32)
    assert_equal SOURCE.b, envelope.source
    assert_equal ID, envelope.request_id
    assert envelope.source.frozen?
    assert_raises(FrozenError) { envelope.source.setbyte(0, 0) }
    refute_includes envelope.inspect, SOURCE
    refute envelope.respond_to?(:token)
    subclass = Class.new(String).new(SOURCE)
    binary_failure(:input) { Yamora::BinaryEnvelope.new(method: 'PUT', collection: 'c', document: 'd', source: subclass) }
    binary_failure(:input) { Yamora::BinaryEnvelope.new(method: 'GET', collection: 'c', document: 'd', source: SOURCE) }
    [false, '0' * 32, 'f' * 31, 'F' * 32].each do |bad|
      binary_failure(:input) { Yamora::BinaryEnvelope.new(method: 'DELETE', collection: 'c', document: 'd', request_id: bad) }
    end
  end

  def test_owned_snapshot_size_and_nonempty_limits
    input = Yamora.const_get(:BinaryInput)
    assert_equal ''.b, input.string('', 4)
    binary_failure(:input) { input.string('', 4, nonempty: true) }
    binary_failure(:input) { input.string('12345', 4) }
    assert_equal '1234'.b, input.string('1234', 4, nonempty: true)
    assert input.string('1234', 4).frozen?
    initial, commands, changed, source = 'original', Queue.new, Queue.new, +'original'
    fired = false
    mutator = Thread.new do
      source.clear if commands.pop == :clear
      changed << true
    end
    trace = TracePoint.new(:c_return) do |event|
      next if fired || event.method_id != :byteslice || !event.self.equal?(source)
      fired = true
      commands << :clear
      await(changed)
    end
    begin
      owned = trace.enable(target_thread: Thread.current) { input.string(source, 16, nonempty: true) }
      assert fired
      assert_equal initial, owned
      assert_empty source
    ensure
      trace.disable
      commands << :stop
      join_owners([mutator])
    end
  end
end
