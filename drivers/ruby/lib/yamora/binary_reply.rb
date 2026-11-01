# frozen_string_literal: true

module Yamora
  module BinaryReply
    module_function

    def protocol!(condition) = BinaryWire.protocol!(condition)

    def integer(bytes, width)
      protocol!(bytes.bytesize == width)
      bytes.unpack1({ 1 => 'C', 2 => 'n', 4 => 'N', 8 => 'Q>' }.fetch(width))
    end

    def text(bytes, maximum, pattern = /\A[\x20-\x7e]+\z/n)
      protocol!(bytes.bytesize <= maximum && pattern.match?(bytes))
      bytes
    end

    def metadata(payload, envelope)
      extended = envelope.respond_to?(:schema) && envelope.schema == 2
      fields = BinaryWire.fields(payload, extended ? 2 : 1)
      values = { status: integer(fields[1], 2), content_type: text(fields[2], 95),
                 body_length: integer(fields[3], 8), representation_length: integer(fields[4], 8),
                 revision: text(fields[5], 16, /\A[0-9a-f]{16}\z/n) }
      { 6 => :etag, 7 => :collection, 8 => :document }.each do |id, name|
        next unless fields.key?(id)
        values[name] = text(fields[id], id == 6 ? 18 : 128, id == 6 ? /\A"[0-9a-f]{16}"\z/n : IDENTIFIER)
      end
      { 9 => [:allow, 1], 10 => [:authenticate, 1], 11 => [:retry_after_seconds, 4] }.each do |id, (name, width)|
        values[name] = integer(fields[id], width) if fields.key?(id)
      end
      if fields.key?(12)
        id = fields[12]
        protocol!(id.bytesize == 16 && id != "\0" * 16)
        values[:request_id] = id.unpack1('H*').freeze
      end
      if extended
        protocol!(fields.key?(13))
        values[:streaming] = integer(fields[13], 1)
        BinaryOperations.correlate(values, envelope)
      else
        correlate(values, envelope)
      end # Bound method-specific lengths before allocation.
      values
    end

    def correlate(r, e)
      status, length, representation = r.values_at(:status, :body_length, :representation_length)
      protocol!(status.between?(200, 599) && length <= MAX_DOCUMENT_BYTES && representation <= MAX_DOCUMENT_BYTES)
      protocol!(length == 0 || length == representation)
      protocol!(status != 204 || (length == 0 && representation == 0))
      protocol!(status != 304 || length == 0)
      protocol!(r[:request_id] == e.request_id)
      protocol!(r[:collection].nil? || r[:collection] == e.collection)
      protocol!(r[:document].nil? || r[:document] == e.document)
      protocol!(e.method == 'HEAD' ? length == 0 : (status == 304 || length == representation))
      protocol!(r[:allow].nil? || (r[:allow].between?(1, 15) && status == 405))
      protocol!(r[:authenticate].nil? || (r[:authenticate] == 1 && status == 401))
      protocol!(r[:retry_after_seconds].nil? || [429, 503].include?(status))
      base = r[:content_type].split(';', 2).first.downcase
      # The metadata grammar permits printable parameters; the base is exact.
      if status >= 400
        protocol!(representation <= 4096 && base == 'application/json')
        return
      end
      case e.method
      when 'GET', 'HEAD'
        protocol!([200, 304].include?(status) && %w[application/yaml text/yaml].include?(base))
        protocol!(!r[:etag].nil? && r[:collection] == e.collection && r[:document] == e.document)
        protocol!(status != 304 || e.if_none_match == '*' || e.if_none_match == r[:etag])
      when 'PUT'
        allowed = e.if_none_match == '*' ? [201] : !e.if_match.nil? ? [200] : [200, 201]
        protocol!(allowed.include?(status) && base == 'application/json' && length.between?(1, 4096) && !r[:etag].nil?)
      when 'DELETE'
        protocol!(status == 204 && length == 0 && representation == 0 && base == 'application/json' && r[:etag].nil?)
      end
    end

    def json(body, budget)
      budget.check
      text = body.dup.force_encoding(Encoding::UTF_8)
      protocol!(text.valid_encoding?)
      begin
        result = JSON.parse(text, max_nesting: 32, create_additions: false, allow_nan: false, allow_duplicate_key: false)
      rescue JSON::ParserError, EncodingError, ArgumentError
        raise BinaryError.new(:protocol, 'yamora: invalid binary JSON response'), cause: nil
      end
      protocol!(result.instance_of?(Hash))
      pending, nodes = [[result, 0]], 0
      until pending.empty?
        value, depth = pending.pop
        nodes += 1
        budget.check if nodes % 64 == 0
        protocol!(nodes <= 1024 && depth <= 32)
        case value
        when Hash
          value.each { |key, item| pending << [key, depth + 1] << [item, depth + 1] }
        when Array
          value.each { |item| pending << [item, depth + 1] }
        when Integer
          protocol!(value.between?(-(2**63), 2**64 - 1))
        when Float
          protocol!(value.finite?)
        end
      end
      budget.check
      result
    end

    def validate(values, body, envelope, budget)
      protocol!(body.bytesize == values[:body_length])
      # Always require valid UTF-8, including error JSON and authored GET bytes.
      body.force_encoding(Encoding::UTF_8)
      protocol!(body.valid_encoding?)
      if values[:status] >= 400
        json(body, budget) unless envelope.method == 'HEAD'
      elsif envelope.method == 'GET' && values[:status] == 200
        protocol!(BinaryWire.source_etag(body, budget) == values[:etag])
      elsif envelope.method == 'PUT'
        receipt = json(body, budget)
        expected = { 'status' => 'stored', 'collection' => envelope.collection, 'document' => envelope.document,
                     'etag' => values[:etag][1, 16], 'revision' => values[:revision] }
        protocol!(receipt == expected && BinaryWire.source_etag(envelope.source, budget) == values[:etag])
      end
      budget.check
      BinaryResponse.new(**values, body: body.freeze)
    end
  end
  private_constant :BinaryReply
end
