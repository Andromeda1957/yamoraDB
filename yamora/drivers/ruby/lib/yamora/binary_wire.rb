# frozen_string_literal: true

module Yamora
  module BinaryWire
    HELLO, REQUEST, RESPONSE, DATA, END_FRAME, CANCEL, ERROR, PING, PONG, GOAWAY = (1..10).to_a
    METHODS = { 'GET' => 1, 'HEAD' => 2, 'PUT' => 3, 'DELETE' => 4, 'POST' => 5, 'PATCH' => 6 }.freeze
    module_function

    def protocol!(condition)
      raise BinaryError.new(:protocol, 'yamora: invalid binary response') unless condition
    end

    def frame(kind, stream, payload = ''.b)
      ['YMBF', 1, kind, 0, stream, payload.bytesize].pack('a4CCnNN') + payload
    end

    # Always called BEFORE reading/allocating any peer payload.
    def header(bytes, cap)
      magic, version, kind, flags, stream, size = bytes.unpack('a4CCnNN')
      protocol!(magic == 'YMBF' && version == 1 && flags == 0 && size <= cap)
      valid = case kind
              when HELLO then stream == 0 && size == 12
              when RESPONSE then stream == 1 && size.between?(1, 2048)
              when DATA then stream == 1 && size.positive?
              when END_FRAME then stream == 1 && size == 0
              when ERROR then stream == 1 && size == 4
              when PING, PONG then stream == 0 && size == 8
              when GOAWAY then stream == 0 && size == 0
              else false
              end
      protocol!(valid)
      [kind, stream, size]
    end

    def hello(cap, protocol = 1) = [1, protocol, cap, 1].pack('nnNN')

    def negotiate(payload, local, protocol = 1)
      low, high, cap, streams = payload.unpack('nnNN')
      protocol!(low && low > 0 && low <= protocol && high >= low && cap.between?(4096, 65_536) && streams.between?(1, 128))
      [local, cap].min
    end

    def encode_fields(fields, schema = 1)
      [schema, fields.size].pack('nn') + fields.map { |id, value| [id, value.bytesize].pack('nn') + value }.join
    end

    def fields(payload, expected_schema = 1)
      protocol!(payload.bytesize.between?(4, 2048))
      schema, count = payload.unpack('nn')
      protocol!(schema == expected_schema && count.between?(5, expected_schema == 2 ? 13 : 12))
      offset, previous, fields = 4, 0, {}
      count.times do
        protocol!(offset + 4 <= payload.bytesize)
        id, size = payload.byteslice(offset, 4).unpack('nn')
        offset += 4
        protocol!(id > previous && id <= (expected_schema == 2 ? 13 : 12) && offset + size <= payload.bytesize)
        fields[id] = payload.byteslice(offset, size).freeze
        previous, offset = id, offset + size
      end
      protocol!(offset == payload.bytesize && (1..5).all? { |id| fields.key?(id) })
      fields
    end

    def request(envelope, token, timeout_ms)
      fields = { 1 => [METHODS.fetch(envelope.method)].pack('C'), 2 => envelope.target,
                 3 => envelope.content_type, 4 => [envelope.source.bytesize].pack('Q>') }
      fields[5] = 'Bearer ' + token if token
      fields[6] = envelope.if_match unless envelope.if_match.nil?
      fields[7] = envelope.if_none_match unless envelope.if_none_match.nil?
      fields[8] = [envelope.request_id].pack('H*') if envelope.request_id
      fields[9] = [timeout_ms].pack('N')
      encode_fields(fields, envelope.respond_to?(:schema) ? envelope.schema : 1)
    end

    def source_etag(source, budget)
      value = 1469598103934665603 # Native seed, deliberately NOT standard FNV.
      offset = 0
      while offset < source.bytesize
        budget.check
        source.byteslice(offset, 4096).each_byte { |byte| value = ((value ^ byte) * 1099511628211) & 0xffffffffffffffff }
        offset += 4096
      end
      budget.check
      format('"%016x"', value)
    end
  end
  private_constant :BinaryWire
end
