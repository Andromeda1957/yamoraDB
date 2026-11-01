# frozen_string_literal: true

module Yamora
  class BinaryError < Error
    attr_reader :kind

    def initialize(kind, message = 'yamora: binary document call failed')
      super(message)
      @kind = kind
    end
  end

  class BinaryUncertainWriteError < BinaryError
    attr_reader :envelope

    def initialize(envelope, kind)
      super(kind, 'yamora: mutation outcome uncertain; retain original envelope for explicit recovery')
      @envelope, @request_id, @uncertain = envelope, envelope.request_id, true
    end
  end

  class BinaryStatusError < BinaryError
    attr_reader :response

    def initialize(response)
      super(:status, "yamora: native document request rejected (#{response.status})")
      @response, @status = response, response.status
    end
  end

  # Signal only. The operation polls it and closes its own socket in ensure.
  # No callbacks, timer threads, Thread#raise or foreign-fiber interruption.
  class BinaryCancellation
    def initialize
      @mutex, @cancelled = Mutex.new, false
    end

    def cancel = @mutex.synchronize { @cancelled = true }
    def cancelled? = @mutex.synchronize { @cancelled }
  end

  module BinaryInput
    module_function

    def require!(condition)
      raise BinaryError.new(:input, 'yamora: invalid binary input') unless condition
    end

    def exact?(value, type) = Object.instance_method(:instance_of?).bind_call(value, type)

    def string(value, limit, nonempty: false)
      require!(exact?(value, String))
      # Use core storage operations, never caller conversion/serialization hooks.
      # Capture at most one excess byte before inspecting size. A caller can
      # mutate its String on another thread between any two Ruby operations.
      owned = String.instance_method(:byteslice).bind_call(value, 0, limit + 1)
      size = owned.bytesize
      require!(size <= limit && (!nonempty || size.positive?))
      owned.force_encoding(Encoding::BINARY).freeze
    end

    def ascii(value, limit, nonempty: false)
      owned = string(value, limit, nonempty: nonempty)
      require!(/\A[\x20-\x7e]*\z/n.match?(owned))
      owned
    end

    def name(value)
      owned = ascii(value, 128, nonempty: true)
      require!(IDENTIFIER.match?(owned))
      owned
    end

    def identity(value)
      owned = ascii(value, 32, nonempty: true)
      require!(/\A[0-9a-f]{32}\z/n.match?(owned) && owned != '0' * 32)
      owned
    end

    def duration(value)
      require!((exact?(value, Integer) || exact?(value, Float)) && value.finite? && value > 0 && value <= 30)
      value.to_f
    end
  end
  private_constant :BinaryInput

  # Owned primitive snapshot. No credentials, caller objects or backing buffers.
  # Construction by the client happens only AFTER admission, under its deadline.
  class BinaryEnvelope
    attr_reader :method, :collection, :document, :target, :source, :if_match, :if_none_match, :request_id, :content_type

    def initialize(method:, collection:, document:, source: '', if_match: nil, if_none_match: nil, request_id: nil)
      @method = BinaryInput.ascii(method, 6, nonempty: true)
      BinaryInput.require!(%w[GET HEAD PUT DELETE].include?(@method))
      @collection, @document = BinaryInput.name(collection), BinaryInput.name(document)
      @target = "/v1/collections/#{@collection}/documents/#{@document}".freeze
      @source = BinaryInput.string(source, MAX_DOCUMENT_BYTES)
      BinaryInput.require!(@method == 'PUT' || @source.empty?)
      BinaryInput.require!(@source.dup.force_encoding(Encoding::UTF_8).valid_encoding?)
      @if_match = if_match.nil? ? nil : BinaryInput.ascii(if_match, 31)
      @if_none_match = if_none_match.nil? ? nil : BinaryInput.ascii(if_none_match, 31)
      mutation = %w[PUT DELETE].include?(@method)
      request_id = OpenSSL::Random.random_bytes(16).unpack1('H*') if mutation && request_id.nil?
      @request_id = request_id.nil? ? nil : BinaryInput.identity(request_id)
      @content_type = (@method == 'PUT' ? 'application/yaml' : '').freeze
      freeze
    end

    def inspect = "#<Yamora::BinaryEnvelope method=#{@method} request_id=#{@request_id} redacted>"
  end

  # Frozen metadata and frozen source/receipt bytes, including all nested values.
  class BinaryResponse
    ATTRIBUTES = %i[status content_type body_length representation_length revision etag collection document allow authenticate retry_after_seconds request_id body streaming resume_after].freeze
    attr_reader(*ATTRIBUTES)

    def initialize(**values)
      ATTRIBUTES.each do |name|
        value = values[name]
        value = value.dup.freeze if value.instance_of?(String)
        instance_variable_set("@#{name}", value)
      end
      freeze
    end

    def inspect = "#<Yamora::BinaryResponse status=#{@status} body=redacted>"
  end
end
