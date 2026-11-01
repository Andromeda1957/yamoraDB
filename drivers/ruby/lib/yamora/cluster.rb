# frozen_string_literal: true

require 'securerandom'

module Yamora
  class DeadlineError < TransportError; end
  class CancelledError < TransportError; end

  class UncertainWriteError < Error
    attr_reader :request_id, :reason

    def initialize(request_id, failure)
      super('yamora: write outcome uncertain; recover the same request ID and exact request', status: failure.status)
      @request_id = request_id.dup.freeze
      @reason = failure.class.name.freeze
      mark_uncertain!
    end
  end

  # Cancel only sockets belonging to this operation. Injecting an exception
  # into a thread can interrupt an unrelated fiber which happens to be running.
  # Decode/validation cancellation is cooperative at the public return guard.
  class Cancellation
    def initialize
      @mutex, @callbacks, @cancelled = Mutex.new, {}, false
    end

    def inspect = '#<Yamora::Cancellation>'
    def cancelled? = @mutex.synchronize { @cancelled }

    def cancel!
      callbacks = @mutex.synchronize do
        return if @cancelled
        @cancelled = true
        @callbacks.values.dup
      end
      callbacks.each(&:call)
      nil
    end

    def register(ticket = Object.new, &callback)
      @mutex.synchronize do
        raise CancelledError, 'yamora: request cancelled' if @cancelled
        @callbacks[ticket] = callback
      end
      ticket
    end

    def unregister(ticket)
      @mutex.synchronize { @callbacks.delete(ticket) }
      nil
    end
  end

  class ClusterTransport
    Route = Struct.new(:index)
    private_constant :Route

    attr_reader :host, :port

    def initialize(seeds:, cluster_id:, voters:, tls:, timeout:, attempt_timeout:, **options)
      Validation.require!(tls.instance_of?(TLS), 'replica sets require verified TLS')
      Validation.require!(Validation.matches?(cluster_id, /\A[0-9a-f]{32}\z/) && cluster_id != '0' * 32, 'invalid cluster ID')
      Validation.require!(voters.is_a?(Integer) && [3, 5, 7, 9].include?(voters), 'invalid voter count')
      duration!(timeout); duration!(attempt_timeout)
      Validation.require!(seeds.is_a?(Array) && seeds.size.between?(1, 9), '1..9 trusted seeds required')
      @cluster_id, @voters = cluster_id.dup.freeze, voters
      seen = {}
      @seeds = seeds.map do |seed|
        Validation.require!(seed.is_a?(Hash) && seed.keys.sort == %i[host node port], 'explicit host, port, node required')
        Validation.integer!(seed[:node], 1, voters)
        endpoint = Transport.new(**seed.reject { |key, _| key == :node }, tls: tls, timeout: attempt_timeout, **options)
        key = [endpoint.host, endpoint.port]
        Validation.require!(!seen[key], 'duplicate seed')
        seen[key] = true
        [endpoint, seed[:node]].freeze
      end.freeze
      @host, @port = @seeds.first.first.host, @seeds.first.first.port
      @timeout, @attempt_timeout = timeout.to_f, attempt_timeout.to_f
      @mutex, @route, @generation, @cursor, @contexts = Mutex.new, nil, 0, 0, {}
    end

    def inspect = '#<Yamora::ClusterTransport verified seeds>'

    def with_request(timeout: @timeout, cancellation: nil, request_id: nil)
      duration!(timeout)
      Validation.require!(cancellation.nil? || cancellation.instance_of?(Cancellation), 'Cancellation required')
      if request_id
        Validation.require!(Validation.matches?(request_id, /\A[0-9a-f]{32}\z/) && request_id != '0' * 32, 'invalid request ID')
        request_id = request_id.dup.freeze
      end
      key = Fiber.current
      previous = @mutex.synchronize { @contexts[key] }
      context = { deadline: now + [timeout.to_f, @timeout].min, cancellation: cancellation, id: request_id, attempts: 0 }
      if previous
        context[:deadline] = [previous[:deadline], context[:deadline]].min
        context[:cancellation] ||= previous[:cancellation]
        context[:id] ||= previous[:id]
        context[:attempts] = previous[:attempts]
      end
      @mutex.synchronize { @contexts[key] = context }
      active!(context)
      result = yield
      active!(context)
      result
    rescue Error => error
      raise error, cause: nil if error.is_a?(UncertainWriteError)
      uncertain = context && context[:uncertain] || false
      id = context && context[:recovery_id]
      error.record_outcome!(uncertain: uncertain, request_id: id)
      raise UncertainWriteError.new(id, error), cause: nil if uncertain
      raise error, cause: nil
    ensure
      if key && context
        @mutex.synchronize do
          if previous
            previous[:attempts] = context[:attempts]
            previous[:uncertain] = context[:uncertain]
            previous[:recovery_id] = context[:recovery_id]
          end
          previous ? @contexts[key] = previous : @contexts.delete(key)
        end
      end
    end

    def request(method, path, body: nil, headers: {}, write: false, **options)
      context = @mutex.synchronize { @contexts[Fiber.current] }
      return with_request { request(method, path, body: body, headers: headers, write: write, **options) } unless context
      if write && !supported_write?(method, path)
        raise HTTPError, 405
      end
      # Freeze caller-owned bytes and every precondition before any I/O.
      body = body&.dup&.freeze
      headers = headers.to_h { |key, value| [key.dup.freeze, value.dup.freeze] }
      id = context[:id]
      if write
        id ||= SecureRandom.hex(16)
        id = SecureRandom.hex(16) while id == '0' * 32
        headers['X-Yamora-Request-Id'] = id
        context[:recovery_id] = id
        context[:uncertain] = false
      end
      headers.freeze
      uncertain = false
      last = HTTPError.new(503)
      delay = 0.05
      action = proc do
        while context[:attempts] < 32
          active!(context)
          # Cached routes only prioritize discovery. A seed can restart with
          # a different binding while its TLS identity and address stay valid.
          route = discover(context)
          if route
            break if context[:attempts] >= 32
            active!(context)
            context[:attempts] += 1
            dispatched = false
            prior_uncertain = uncertain
            begin
              result = @seeds[route.index].first.request(method, path, body: body, headers: headers, write: write,
                          **options, timeout: budget(context, @seeds.size > 1 ? 2 : 1), cancellation: context[:cancellation],
                          on_dispatch: -> {
                            dispatched = true
                            if write
                              uncertain = true
                              context[:uncertain] = true
                            end
                          })
              receipt!(method, path, body, result) if write
              active!(context)
              return result
            rescue Error => error
              definitive = error.is_a?(HTTPError) && error.status.between?(400, 499) && error.status != 408
              uncertain = prior_uncertain if definitive || !dispatched
              context[:uncertain] = uncertain if write
              last = error
              active!(context)
              raise unless error.is_a?(TransportError) || error.is_a?(HTTPError) && error.status == 503
              @mutex.synchronize do
                if @route.equal?(route)
                  @route = nil
                  @generation += 1
                  @cursor = (route.index + 1) % @seeds.size
                end
              end
            end
          end
          active!(context)
          sleep [0, [delay, context[:deadline] - now].min].max
          delay = [1.0, delay * 2].min
        end
        active!(context)
        raise last
      end
      # Socket cancellation is bound to the exact exchange, while the public
      # operation context survives through decoding and semantic validation.
      begin
        action.call
      rescue Error => error
        # Transport's standalone uncertainty is deliberately conservative even
        # before TLS completes; the cluster knows whether dispatch started.
        error.record_outcome!(uncertain: uncertain, request_id: write ? id : nil)
        raise UncertainWriteError.new(id, error), cause: nil if write && uncertain
        raise error, cause: nil
      end
    end

    private

    def now = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    def duration!(duration)
      Validation.require!(duration.is_a?(Numeric) && duration.real? && duration.finite? && duration > 0 && duration <= 30 && duration.to_f > 0, 'timeout must be in (0, 30] seconds')
    end

    def active!(context)
      raise CancelledError, 'yamora: request cancelled' if context[:cancellation]&.cancelled?
      raise DeadlineError, 'yamora: replica-set deadline exceeded' if now >= context[:deadline]
    end

    def budget(context, shares)
      active!(context)
      remaining = context[:deadline] - now
      raise DeadlineError, 'yamora: replica-set deadline exceeded' unless remaining > 0
      [@attempt_timeout, remaining / shares].min
    end

    def discover(context)
      start, generation = @mutex.synchronize { [@route&.index || @cursor, @generation] }
      @seeds.size.times do |offset|
        return nil if context[:attempts] >= 32
        active!(context)
        index = (start + offset) % @seeds.size
        endpoint, expected_node = @seeds[index]
        context[:attempts] += 1
        begin
          # Reserve time for the identity check, final dispatch and later seeds.
          response = endpoint.request('GET', '/v1/cluster/status', maximum: 4096,
                                       timeout: budget(context, @seeds.size - offset + 2), cancellation: context[:cancellation])
          value = json!(response)
          valid = value['node'].is_a?(Integer) && value['node'] == expected_node &&
                  value['leader'].is_a?(Integer) && value['leader'] == expected_node &&
                  value['voters'].is_a?(Integer) && value['voters'] == @voters &&
                  value['term'].is_a?(Integer) && value['term'].between?(1, 2**64 - 1) && value['role'] == 'leader'
          next unless valid
          return nil if context[:attempts] >= 32
          context[:attempts] += 1
          feed = json!(endpoint.request('GET', '/v1/changes', maximum: 4096,
                                       timeout: budget(context, @seeds.size - offset + 1), cancellation: context[:cancellation]))
          next unless %w[checkpoint next_after oldest_after].all? { |key| Validation.matches?(feed[key], CHANGE_TOKEN) && feed[key][3, 32] == @cluster_id } &&
                      feed['transactions'] == [] && feed['has_more'] == false && feed['checkpoint'] == feed['next_after']
          route = Route.new(index).freeze
          @mutex.synchronize do
            if @generation == generation
              @route = route
              @generation += 1
              @cursor = (index + 1) % @seeds.size
            end
          end
          return route
        rescue Error => error
          raise if error.is_a?(CancelledError) || error.is_a?(HTTPError) && [401, 403].include?(error.status)
          active!(context)
        end
      end
      @mutex.synchronize { @cursor = (start + 1) % @seeds.size if generation == @generation }
      nil
    end

    def supported_write?(method, path)
      method == 'POST' && path == '/v1/transactions' || method == 'PUT' && path == '/v1/indexes' ||
        %w[PUT PATCH DELETE].include?(method) && %r{\A/v1/collections/[a-z0-9-]{1,128}/documents/[a-z0-9-]{1,128}\z}.match?(path)
    end

    def protocol!(valid)
      raise ProtocolError, 'yamora: invalid cluster receipt or identity' unless valid
    end

    def json!(response)
      body, headers = response
      protocol!((headers['content-type'] || '').split(';', 2).first.to_s.strip.downcase == 'application/json')
      protocol!(Validation.matches?(headers['x-yamldb-revision'], REVISION))
      text = body.dup.force_encoding(Encoding::UTF_8)
      protocol!(text.valid_encoding?)
      value = JSON.parse(text, max_nesting: 64, create_additions: false, allow_nan: false, allow_duplicate_key: false)
      protocol!(value.is_a?(Hash) && finite_json?(value))
      value
    rescue JSON::ParserError, EncodingError, ArgumentError
      raise ProtocolError, 'yamora: invalid cluster JSON', cause: nil
    end

    def finite_json?(value)
      case value
      when Float then value.finite?
      when Array then value.all? { |item| finite_json?(item) }
      when Hash then value.each_value.all? { |item| finite_json?(item) }
      else true
      end
    end

    def receipt!(method, path, body, response)
      payload, headers, status = response
      revision = headers['x-yamldb-revision']
      protocol!(Validation.matches?(revision, REVISION))
      if method == 'DELETE'
        protocol!(status == 204 && payload.empty?)
        return
      end
      value = json!(response)
      protocol!(value['revision'] == revision)
      if path.start_with?('/v1/collections/')
        parts = path.split('/')
        protocol!(%w[PUT PATCH].include?(method) && (status == 200 || method == 'PUT' && status == 201) &&
                  value['status'] == 'stored' && value['collection'] == parts[3] && value['document'] == parts[5] && Validation.matches?(value['etag'], REVISION))
        protocol!(headers['etag'] == %Q("#{value['etag']}"))
      else
        count = path == '/v1/indexes' ? 1 : JSON.parse(body)['operations'].size
        protocol!(status == 200 && value['status'] == 'committed' && value['operations'].is_a?(Integer) && value['operations'] == count)
        protocol!(headers['etag'].nil? || headers['etag'] == %Q("#{revision}"))
      end
    end
  end
  private_constant :ClusterTransport

  class ClusterClient < Client
    def initialize(seeds:, cluster_id:, voters:, tls:, timeout: 5, attempt_timeout: 1,
                   read_token: nil, write_token: nil, max_response_bytes: MAX_RESPONSE_BYTES)
      @transport = ClusterTransport.new(seeds: seeds, cluster_id: cluster_id, voters: voters, tls: tls,
                     timeout: timeout, attempt_timeout: attempt_timeout, read_token: read_token,
                     write_token: write_token, max_response_bytes: max_response_bytes)
      freeze
    end

    def inspect = '#<Yamora::ClusterClient verified seeds>'
    def with_request(timeout: 30, cancellation: nil, &block)
      @transport.with_request(timeout: timeout, cancellation: cancellation) { block.call(self) }
    end

    # The whole public call, including inherited decoding and semantic checks,
    # shares the same deadline/cancellation context as discovery and exchange.
    %i[health ready stats metrics collections document_page get query count
       aggregate search indexes index_build changes replication_status
       start_index_build cancel_index_build].each do |operation|
      define_method(operation) do |*args, **options, &block|
        @transport.with_request { super(*args, **options, &block) }
      end
    end

    def put(*args, request_id: nil, **options)
      @transport.with_request(request_id: request_id) { super(*snapshot(args), **snapshot(options)) }
    end

    def patch(*args, request_id: nil, **options)
      @transport.with_request(request_id: request_id) { super(*snapshot(args), **snapshot(options)) }
    end

    def delete(*args, request_id: nil, **options)
      @transport.with_request(request_id: request_id) { super(*snapshot(args), **snapshot(options)) }
    end

    def transaction(*args, request_id: nil, **options)
      @transport.with_request(request_id: request_id) { super(*snapshot(args), **snapshot(options)) }
    end

    def set_indexes(*args, request_id: nil, **options)
      @transport.with_request(request_id: request_id) { super(*snapshot(args), **snapshot(options)) }
    end

    private

    # ClusterTransport validates all accepted mutation semantics before identity
    # leaves its recovery boundary. Unsupported jobs reject before any dispatch.
    def snapshot(value)
      if value.is_a?(Hash)
        value.to_h { |key, item| [key, Validation.json_value(item)] }
      else
        Validation.json_value(value)
      end
    end

    def mutate = yield
  end
end
