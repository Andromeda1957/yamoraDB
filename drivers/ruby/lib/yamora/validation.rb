# frozen_string_literal: true

module Yamora
  MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
  MAX_REQUEST_BYTES = 64 * 1024 * 1024
  MAX_RESPONSE_BYTES = 64 * 1024 * 1024
  IDENTIFIER = /\A[a-z0-9-]{1,128}\z/
  REVISION = /\A[0-9a-f]{16}\z/
  CHANGE_TOKEN = /\Av1\.[0-9a-f]{32}\.[0-9a-f]{16}\z/

  class Error < StandardError
    attr_reader :status, :request_id

    def initialize(message, status: nil)
      super(message)
      @status = status
      @uncertain = false
    end

    def uncertain? = @uncertain

    # Cluster routing knows whether bytes could have reached a writer.
    def record_outcome!(uncertain:, request_id: nil)
      @uncertain = uncertain
      @request_id = request_id&.dup&.freeze
      self
    end

    # Conservative: a failed write acknowledgement cannot prove rollback.
    def mark_uncertain!
      @uncertain = true
      self
    end
  end

  class HTTPError < Error
    def initialize(status)
      super("yamora: HTTP #{status}", status: status)
    end
  end
  class TransportError < Error; end
  class SchemaPolicyReplicationError < Error
    def initialize
      super('yamora: schema_policy_replication_unsupported', status: 409)
    end
  end
  class ProtocolError < Error; end
  class RevisionError < ProtocolError; end
  class LimitError < ProtocolError; end

  module Validation
    module_function

    def require!(condition, message = 'invalid arguments')
      raise ArgumentError, "yamora: #{message}" unless condition
    end

    def matches?(value, pattern)
      value.is_a?(String) && value.ascii_only? && pattern.match?(value)
    end

    def identifier!(value)
      require!(matches?(value, IDENTIFIER), 'invalid identifier')
      value
    end

    def revision!(value)
      require!(matches?(value, REVISION), 'invalid revision or ETag')
      value
    end

    def optional_revision!(value)
      revision!(value) unless value.nil?
    end

    def integer!(value, minimum, maximum)
      require!(value.is_a?(Integer) && value.between?(minimum, maximum), 'integer outside bounds')
    end

    def boolean!(value)
      require!(value == true || value == false, 'boolean required')
    end

    # Interpret strings as UTF-8 bytes, without transcoding authored source.
    def utf8!(value, maximum, nonempty: false)
      require!(value.is_a?(String), 'UTF-8 string required')
      require!(value.bytesize <= maximum && (!nonempty || !value.empty?), 'string outside byte bounds')
      result = String.new(value).force_encoding(Encoding::UTF_8)
      require!(result.valid_encoding?, 'invalid UTF-8')
      result
    end

    def source!(value)
      utf8!(value, MAX_DOCUMENT_BYTES, nonempty: true)
    end

    def preconditions(etag, create_only = false)
      boolean!(create_only)
      optional_revision!(etag)
      require!(!(etag && create_only), 'conflicting preconditions')
      return { 'If-Match' => %Q("#{etag}") } if etag
      create_only ? { 'If-None-Match' => '*' } : {}
    end

    # Normalize only JSON primitives; never invoke caller-defined to_json hooks.
    # Budget before encoding prevents cycles/deep containers and large expansion.
    def json_value(value, depth = 0, budget = [100_000, MAX_REQUEST_BYTES])
      budget[0] -= 1
      require!(depth <= 64 && budget[0] >= 0 && budget[1] >= 0, 'JSON complexity limit')
      case value
      when Hash
        value.each_with_object({}) do |(key, item), result|
          require!(key.is_a?(String), 'JSON keys must be strings')
          result[json_value(key, depth + 1, budget)] = json_value(item, depth + 1, budget)
        end
      when Array
        value.map { |item| json_value(item, depth + 1, budget) }
      when String
        text = utf8!(value, MAX_REQUEST_BYTES)
        budget[1] -= text.bytesize
        require!(budget[1] >= 0, 'JSON byte limit')
        text
      when Integer
        require!(value.between?(-(2**63), 2**64 - 1), 'integer outside protocol range')
        value
      when Float
        require!(value.finite?, 'nonfinite JSON number')
        value
      when true, false, nil
        value
      else
        require!(false, 'JSON primitives required')
      end
    end

    def encode(value, maximum)
      # LibYAML treats NEL, line separator and paragraph separator as breaks
      # even inside JSON strings. Escape them without changing their values.
      body = JSON.generate(json_value(value), max_nesting: 65).gsub(/[\u0085\u2028\u2029]/) do |separator|
        format('\\u%04x', separator.ord)
      end
      require!(body.bytesize <= maximum, 'request exceeds byte limit')
      body
    end

    def indexes!(definitions)
      require!(definitions.is_a?(Array) && definitions.size <= 64, 'invalid index catalog')
      seen = {}
      definitions.each do |index|
        require!(index.is_a?(Hash) && (index.keys - %w[collection name fields unique type]).empty?, 'invalid index')
        identifier!(index['collection'])
        identifier!(index['name'])
        key = [index['collection'], index['name']]
        require!(!seen[key], 'duplicate index')
        seen[key] = true
        boolean!(index.fetch('unique', false))
        require!(!index.key?('type') || index['type'] == 'text', 'invalid index type')
        require!(!(index['type'] == 'text' && index['unique']), 'text index cannot be unique')
        fields = index['fields']
        require!(fields.is_a?(Array) && fields.size.between?(1, 8) && fields.uniq.size == fields.size, 'invalid index fields')
        fields.each { |field| utf8!(field, 1024, nonempty: true) }
        require!(!fields.include?('$source') || (index['type'] == 'text' && fields == ['$source']), 'invalid source index')
      end
    end

    def operations!(operations)
      require!(operations.is_a?(Array) && operations.size.between?(1, 128), 'invalid transaction')
      seen = {}
      operations.each do |op|
        require!(op.is_a?(Hash) && (op.keys - %w[collection document put patch delete etag create_only]).empty?, 'invalid operation')
        identifier!(op['collection'])
        identifier!(op['document'])
        key = [op['collection'], op['document']]
        require!(!seen[key], 'duplicate transaction target')
        seen[key] = true
        selected = op.keys & %w[put patch delete]
        require!(selected.size == 1, 'select exactly one mutation')
        source!(op['put']) if op.key?('put')
        require!(op['patch'].is_a?(Hash) && !op['patch'].empty?, 'nonempty patch required') if op.key?('patch')
        require!(op['delete'] == true, 'delete must be true') if op.key?('delete')
        preconditions(op['etag'], op.fetch('create_only', false))
        require!(!op['create_only'] || op.key?('put'), 'create_only requires put')
      end
    end
  end
end
