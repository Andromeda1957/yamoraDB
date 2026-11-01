# frozen_string_literal: true

module Yamora
  # Immutable original schema-2 operation. Raw specification bytes are retained
  # exactly; this envelope contains no credentials or caller-owned objects.
  class BinaryOperationEnvelope
    attr_reader :method, :target, :content_type, :source, :if_match, :if_none_match,
                :request_id, :collection, :document, :after
    def schema = 2
    def mutation? = @method == 'PATCH' || @target == '/v1/transactions'
    def initialize(method, target, content_type, source, if_match: nil, if_none_match: nil, request_id: nil, feed: false)
      @method, @target = BinaryInput.ascii(method, 5, nonempty: true), BinaryInput.ascii(target, 1024, nonempty: true)
      @content_type = BinaryInput.ascii(content_type, 95)
      @source = BinaryInput.string(source, MAX_DOCUMENT_BYTES)
      BinaryInput.require!(@source.dup.force_encoding(Encoding::UTF_8).valid_encoding?)
      doc = %r{\A/v1/collections/([a-z0-9-]{1,128})/documents/([a-z0-9-]{1,128})\z}.match(@target)
      query = %r{\A/v1/(query|aggregate|search)/([a-z0-9-]{1,128})\z}.match(@target)
      stream = @target.start_with?('/v1/changes/stream?')
      changes = %r{\A/v1/changes(?:\?[^%#]*)?\z}.match?(@target)
      BinaryInput.require!(@method == 'PATCH' && doc || @method == 'POST' && (query || @target == '/v1/transactions') || @method == 'GET' && (changes || stream))
      BinaryInput.require!(feed == stream)
      @collection, @document = doc ? doc.captures : [query&.[](2), nil]
      if @method == 'GET'
        BinaryInput.require!(@content_type.empty? && @source.empty?)
        seen = {}
        (@target.split('?', 2)[1] || '').split('&').each do |part|
          match = /\A(after|limit|duration_ms|heartbeat_ms)=([a-z0-9.]+)\z/n.match(part)
          BinaryInput.require!(match && !seen[match[1]] && (stream || %w[after limit].include?(match[1])))
          seen[match[1]] = true
          BinaryInput.require!(match[1] == 'after' ? /\Av1\.[0-9a-f]{32}\.[0-9a-f]{16}\z/n.match?(match[2]) : /\A[0-9]+\z/n.match?(match[2]))
          @after = match[2].freeze if match[1] == 'after'
        end
        BinaryInput.require!(!stream || @after)
      else
        BinaryInput.require!(%r{\A(application/(json|yaml)|text/yaml)(;[\x20-\x7e]*)?\z}i.match?(@content_type))
      end
      @if_match = if_match.nil? ? nil : BinaryInput.ascii(if_match, 31)
      @if_none_match = if_none_match.nil? ? nil : BinaryInput.ascii(if_none_match, 31)
      @request_id = BinaryInput.identity(request_id || OpenSSL::Random.random_bytes(16).unpack1('H*'))
      @collection&.freeze; @document&.freeze
      freeze
    end
    def inspect = "#<Yamora::BinaryOperationEnvelope method=#{@method} request_id=#{@request_id} redacted>"
  end

  module BinaryOperations
    module_function
    def protocol!(ok) = BinaryWire.protocol!(ok)
    def json(body, budget, max_nesting: 64)
      budget.check
      text = body.dup.force_encoding(Encoding::UTF_8)
      protocol!(text.valid_encoding?)
      value = JSON.parse(text, max_nesting: max_nesting, create_additions: false, allow_nan: false, allow_duplicate_key: false)
      protocol!(value.instance_of?(Hash))
      budget.check
      value
    rescue JSON::ParserError, EncodingError, ArgumentError
      raise BinaryError.new(:protocol), cause: nil
    end
    def correlate(r, e)
      status, length, representation, mode = r.values_at(:status, :body_length, :representation_length, :streaming)
      protocol!(status.between?(200, 599) && [0, 1].include?(mode) && length <= MAX_DOCUMENT_BYTES && length == representation && r[:request_id] == e.request_id)
      protocol!(r[:collection].nil? || r[:collection] == e.collection)
      protocol!(r[:document].nil? || r[:document] == e.document)
      protocol!(r[:allow].nil? || r[:allow].between?(1, 63) && status == 405)
      protocol!(r[:authenticate].nil? || r[:authenticate] == 1 && status == 401)
      protocol!(r[:retry_after_seconds].nil? || [429, 503].include?(status))
      media = r[:content_type].split(';', 2).first.downcase
      if status >= 400
        protocol!(mode == 0 && length <= 4096 && media == 'application/json')
      else
        protocol!(status == 200)
        feed = e.target.start_with?('/v1/changes/stream?')
        protocol!(mode == (feed ? 1 : 0) && (feed ? length == 0 && media == 'application/x-ndjson' : media == 'application/json'))
        protocol!(!e.mutation? || length.between?(1, 4096))
        protocol!(e.method != 'PATCH' || r[:etag])
      end
    end
    def validate(values, body, e, budget)
      protocol!(body.bytesize == values[:body_length])
      # Native values gain query/facet envelope containers in responses.
      value = json(body, budget, max_nesting: 80)
      if values[:status] < 400
        protocol!(value['revision'] == values[:revision])
        if e.method == 'PATCH'
          expected = { 'status' => 'stored', 'collection' => e.collection, 'document' => e.document,
                       'revision' => values[:revision], 'etag' => values[:etag][1, 16] }
          protocol!(value == expected)
        elsif e.mutation?
          protocol!(value.keys.sort == %w[operations revision status] && value['status'] == 'committed' && value['operations'].instance_of?(Integer) && value['operations'].between?(1, 128))
          if e.content_type.split(';', 2).first.downcase == 'application/json'
            request = json(e.source, budget)
            protocol!(request['operations'].instance_of?(Array) && value['operations'] == request['operations'].size)
          end
        end
      end
      BinaryResponse.new(**values, body: body.freeze)
    end
    def feed_page(raw, after, budget)
      protocol!(raw.end_with?("\n"))
      p = json(raw, budget, max_nesting: 80)
      if p.key?('terminal')
        protocol!(p['terminal'] == true)
        protocol!(p['status'].instance_of?(Integer) && p['status'].between?(400, 599) && p['after'] == after && p['detail'].instance_of?(Hash))
        return [after, true]
      end
      token = /\Av1\.[0-9a-f]{32}\.[0-9a-f]{16}\z/
      protocol!(%w[next_after oldest_after checkpoint].all? { |key| p[key].instance_of?(String) && token.match?(p[key]) })
      protocol!(/\A[0-9a-f]{16}\z/.match?(p['revision'].to_s) && p['transactions'].instance_of?(Array) && p['transactions'].size <= 100)
      protocol!([true, false].include?(p['has_more']) && p['oldest_after'] <= p['next_after'] && p['next_after'] <= p['checkpoint'] && p['has_more'] == (p['next_after'] < p['checkpoint']))
      protocol!(p['next_after'][0, 36] == p['checkpoint'][0, 36] && p['oldest_after'][0, 36] == p['checkpoint'][0, 36] && p['next_after'][0, 36] == after[0, 36] && p['next_after'] >= after)
      previous = after
      previous_revision = nil
      p['transactions'].each do |frame|
        protocol!(frame.instance_of?(Hash) && token.match?(frame['token'].to_s) && frame['token'][0, 36] == after[0, 36] && frame['token'] > previous && frame['token'] <= p['checkpoint'])
        protocol!(/\A[0-9a-f]{16}\z/.match?(frame['revision'].to_s) && /\A[0-9a-f]{16}\z/.match?(frame['previous_revision'].to_s) && [true, false].include?(frame['resnapshot_required']) && frame['operations'].instance_of?(Array) && frame['operations'].size <= 256)
        protocol!(!frame['resnapshot_required'] || frame['operations'].empty?)
        protocol!(previous_revision.nil? || previous_revision == frame['previous_revision'])
        seen, source_bytes = {}, 0
        frame['operations'].each do |op|
          protocol!(op.instance_of?(Hash) && op['collection'].instance_of?(String) && /\A[a-z0-9-]{1,128}\z/.match?(op['collection']))
          key = [op['collection'], op['document']]
          protocol!(!seen[key]); seen[key] = true
          if op.key?('document')
            protocol!(op['document'].instance_of?(String) && /\A[a-z0-9-]{1,128}\z/.match?(op['document']) && op.size == 3 &&
                      (op['put'].instance_of?(String) && op['put'].bytesize.between?(1, MAX_DOCUMENT_BYTES) || op['delete'] == true))
            source_bytes += op['put'].bytesize if op['put'].instance_of?(String)
          else
            protocol!(op.size == 2 && op['create_collection'] == true)
          end
        end
        protocol!(source_bytes <= MAX_DOCUMENT_BYTES)
        previous = frame['token']
        previous_revision = frame['revision']
      end
      protocol!(p['transactions'].empty? ? !p['has_more'] && p['next_after'] == after : previous == p['next_after'])
      [p['next_after'], false]
    end
  end
  private_constant :BinaryOperations

  class BinaryClient
    # Explicit raw schema-2 API. Credentials remain per-call, as with source CRUD.
    def operation(method, target, content_type, source = '', token: nil, timeout: @config.timeout, cancel: nil, **conditions)
      execute(timeout, cancel, token) { BinaryOperationEnvelope.new(method, target, content_type, source, **conditions) }
    end
    # The block receives one frozen raw page including LF and immutable metadata.
    def feed(target, token: nil, timeout: @config.timeout, cancel: nil, **conditions, &consume)
      BinaryInput.require!(!consume.nil?)
      execute(timeout, cancel, token, page: consume) { BinaryOperationEnvelope.new('GET', target, '', '', feed: true, **conditions) }
    end
  end
end
