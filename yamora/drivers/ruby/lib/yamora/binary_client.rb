# frozen_string_literal: true

module Yamora
  class BinaryBudget
    def initialize(deadline, cancel, client)
      @deadline, @cancel, @client = deadline, cancel, client
    end

    def check
      raise BinaryError.new(:closed, 'yamora: binary client closed') if @client.closed?
      raise BinaryError.new(:cancelled, 'yamora: binary call cancelled') if @cancel&.cancelled?
      remaining = @deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      raise BinaryError.new(:timeout, 'yamora: binary deadline exceeded') if remaining <= 0
      remaining
    end

    def wait(socket, writing)
      duration = [check, 0.02].min
      IO.select(writing ? nil : [socket], writing ? [socket] : nil, nil, duration)
      check
    end
  end

  class BinaryChannel
    attr_accessor :cap

    def initialize(socket, budget, cap)
      @socket, @budget, @cap = socket, budget, cap
    end

    def io
      loop do
        @budget.check
        result = yield
        case result
        when :wait_readable then @budget.wait(@socket, false)
        when :wait_writable then @budget.wait(@socket, true)
        else return result
        end
      end
    end

    def send_frame(kind, stream, payload = ''.b)
      bytes = BinaryWire.frame(kind, stream, payload)
      offset = 0
      while offset < bytes.bytesize
        part = bytes.byteslice(offset, bytes.bytesize - offset)
        # Preserve identical bytes during SSL WANT retries.
        count = io { @socket.write_nonblock(part, exception: false) }
        raise EOFError unless count && count > 0
        offset += count
      end
    end

    def exact(size)
      bytes = +''.b
      while bytes.bytesize < size
        part = io { @socket.read_nonblock(size - bytes.bytesize, exception: false) }
        raise EOFError if part.nil? || part.empty?
        bytes << part
      end
      bytes
    end

    def receive(remaining: nil)
      kind, stream, size = BinaryWire.header(exact(16), @cap)
      BinaryWire.protocol!(!remaining.nil? && size <= remaining) if kind == BinaryWire::DATA
      [kind, stream, exact(size)]
    end
  end
  private_constant :BinaryBudget, :BinaryChannel

  class BinaryClient
    attr_reader :config

    def initialize(config)
      BinaryInput.require!(BinaryInput.exact?(config, BinaryConfig) && config.frozen?)
      @config = config
      @mutex, @condition, @active, @closed = Mutex.new, ConditionVariable.new, 0, false
    end

    def inspect = "#<Yamora::BinaryClient #{@config.host}:#{@config.port}>"
    def closed? = @mutex.synchronize { @closed }
    def get(collection, document, **options) = request('GET', collection, document, **options)
    def head(collection, document, **options) = request('HEAD', collection, document, **options)
    def put(collection, document, source, **options) = request('PUT', collection, document, source: source, **options)
    def delete(collection, document, **options) = request('DELETE', collection, document, **options)

    def request(method, collection, document, source: '', token: nil, if_match: nil, if_none_match: nil,
                request_id: nil, timeout: @config.timeout, cancel: nil)
      execute(timeout, cancel, token) do
        BinaryEnvelope.new(method: method, collection: collection, document: document, source: source,
                           if_match: if_match, if_none_match: if_none_match, request_id: request_id)
      end
    end

    # Only an already validated immutable envelope can explicitly repeat a call.
    # Standalone stores do NOT acquire a deduplication guarantee from its ID.
    def replay(envelope, token: nil, timeout: @config.timeout, cancel: nil)
      BinaryInput.require!(BinaryInput.exact?(envelope, BinaryEnvelope) && envelope.frozen?)
      execute(timeout, cancel, token) { envelope }
    end

    def close(timeout: 1)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + BinaryInput.duration(timeout)
      @mutex.synchronize do
        @closed = true
        @condition.broadcast
        while @active > 0
          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          raise BinaryError.new(:timeout, 'yamora: binary owners have not closed') if remaining <= 0
          @condition.wait(@mutex, [remaining, 0.02].min)
        end
      end
      nil
    end

    private

    def execute(timeout, cancel, token, page: nil)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      # This synchronous execution model supports threads and ordinary fibers.
      # Scheduler interception of IO/select could couple unrelated fiber owners.
      BinaryInput.require!(Fiber.scheduler.nil? && (cancel.nil? || BinaryInput.exact?(cancel, BinaryCancellation)))
      budget = BinaryBudget.new(started + BinaryInput.duration(timeout), cancel, self)
      admitted = false
      # Waiters retain caller references only. No copied source, context or socket.
      loop do
        remaining = budget.check
        admitted = @mutex.synchronize do
          if !@closed && @active < @config.concurrency
            @active += 1
            true
          else
            @condition.wait(@mutex, [remaining, 0.02].min)
            false
          end
        end
        break if admitted
      end
      envelope, dispatched, socket, tls = nil, false, nil, nil
      begin
        budget.check
        envelope = yield
        budget.check
        bearer = token.nil? ? nil : BinaryInput.ascii(token, 512, nonempty: true)
        BinaryInput.require!(bearer.nil? || !bearer.include?(' '))
        budget.check
        context = @config.send(:context, budget)
        budget.check
        socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
        destination = Socket.sockaddr_in(@config.port, @config.host) # Numeric route only.
        loop do
          budget.check
          result = socket.connect_nonblock(destination, exception: false)
          break if result == 0
          budget.wait(socket, true)
        rescue Errno::EISCONN
          break
        end
        budget.check
        tls = OpenSSL::SSL::SSLSocket.new(socket, context)
        tls.sync_close = true
        tls.hostname = @config.server_name
        channel = BinaryChannel.new(tls, budget, @config.max_frame)
        channel.io { tls.connect_nonblock(exception: false) }
        # post_connection_check validates SAN (with OpenSSL's CN fallback).
        # Require a matching SAN separately so a CN can never authorize identity.
        BinaryWire.protocol!(tls.ssl_version == 'TLSv1.3' && tls.alpn_protocol == 'yamora-binary/1')
        BinaryWire.protocol!(matching_san?(tls.peer_cert, @config.server_name))
        tls.post_connection_check(@config.server_name)
        budget.check
        channel.send_frame(BinaryWire::HELLO, 0, BinaryWire.hello(@config.max_frame, envelope.respond_to?(:schema) ? 2 : 1))
        kind, stream, payload = channel.receive
        BinaryWire.protocol!(kind == BinaryWire::HELLO && stream == 0)
        channel.cap = BinaryWire.negotiate(payload, @config.max_frame, envelope.respond_to?(:schema) ? 2 : 1)
        if envelope.respond_to?(:schema) && payload.unpack('nn')[1] < 2
          raise BinaryError.new(:unsupported, 'yamora: binary operation protocol unavailable')
        end
        metadata = BinaryWire.request(envelope, bearer, [[(budget.check * 1000).floor, 1].max, 30_000].min)
        budget.check
        dispatched = true # REQUEST may partially leave the socket from this point.
        channel.send_frame(BinaryWire::REQUEST, 1, metadata)
        offset = 0
        while offset < envelope.source.bytesize
          channel.send_frame(BinaryWire::DATA, 1, envelope.source.byteslice(offset, channel.cap))
          offset += channel.cap
        end
        channel.send_frame(BinaryWire::END_FRAME, 1)
        values, body, controls = nil, +''.b, 0
        total, terminal = 0, false
        after = envelope.respond_to?(:after) ? envelope.after : nil
        loop do
          kind, _, payload = channel.receive(remaining: values && (values[:streaming] == 1 ? MAX_DOCUMENT_BYTES - total : values[:body_length] - body.bytesize))
          case kind
          when BinaryWire::PING
            controls += 1
            BinaryWire.protocol!(controls <= 16)
            channel.send_frame(BinaryWire::PONG, 0, payload)
          when BinaryWire::RESPONSE
            BinaryWire.protocol!(values.nil?)
            values = BinaryReply.metadata(payload, envelope)
          when BinaryWire::DATA
            BinaryWire.protocol!(values && !terminal)
            if values[:streaming] == 1
              total += payload.bytesize
              BinaryWire.protocol!(total <= MAX_DOCUMENT_BYTES)
              body << payload
              while (newline = body.index("\n"))
                raw = body.byteslice(0, newline + 1).freeze
                body = body.byteslice(newline + 1, body.bytesize - newline - 1)
                following, terminal = BinaryOperations.feed_page(raw, after, budget)
                page.call(raw, BinaryResponse.new(**values, body: '', resume_after: following))
                after = following
                budget.check
                BinaryWire.protocol!(!terminal || body.empty?)
              end
            else
              BinaryWire.protocol!(payload.bytesize <= values[:body_length] - body.bytesize)
              body << payload
            end
          when BinaryWire::END_FRAME
            BinaryWire.protocol!(!values.nil?)
            response = if values[:streaming] == 1
                         BinaryWire.protocol!(body.empty?)
                         BinaryResponse.new(**values, body: '', resume_after: after)
                       elsif envelope.respond_to?(:schema)
                         BinaryOperations.validate(values, body, envelope, budget)
                       else
                         BinaryReply.validate(values, body, envelope, budget)
                       end
            budget.check # Final guard includes decode and native identity hashing.
            if mutation_envelope?(envelope) && (response.status >= 500 || response.status == 408)
              raise BinaryUncertainWriteError.new(envelope, :status)
            end
            raise BinaryStatusError.new(response) if response.status >= 400
            return response
          when BinaryWire::ERROR
            BinaryWire.protocol!(payload.unpack1('N') != 0)
            raise BinaryError.new(:session, 'yamora: session ERROR cannot establish an operation outcome')
          when BinaryWire::GOAWAY
            raise BinaryError.new(:session, 'yamora: binary peer entered drain')
          else
            BinaryWire.protocol!(false)
          end
        end
      rescue BinaryStatusError, BinaryUncertainWriteError
        raise
      rescue StandardError => error
        kind = error.is_a?(BinaryError) ? error.kind : error.is_a?(OpenSSL::OpenSSLError) ? :tls : :transport
        if dispatched && mutation_envelope?(envelope)
          raise BinaryUncertainWriteError.new(envelope, kind), cause: nil
        end
        raise BinaryError.new(kind), cause: nil
      ensure
        # Only this call closes its handles. No cancellation callback can outlive
        # ownership or close a descriptor reused by a neighboring call.
        begin
          tls&.close
        rescue IOError, SystemCallError, OpenSSL::OpenSSLError
          nil
        ensure
          begin
            socket&.close unless socket&.closed?
          ensure
            @mutex.synchronize do
              @active -= 1
              @condition.broadcast
            end
          end
        end
      end
    end

    def mutation_envelope?(envelope)
      envelope.respond_to?(:mutation?) ? envelope.mutation? : %w[PUT DELETE].include?(envelope.method)
    end

    def matching_san?(certificate, identity)
      san = certificate.extensions.select { |extension| extension.oid == 'subjectAltName' }
      return false unless san.size == 1
      encoded = OpenSSL::ASN1.decode(san.first.to_der).value.last.value
      names = OpenSSL::ASN1.decode(encoded)
      return false unless names.to_der == encoded
      numeric = /\A[0-9]+(?:\.[0-9]+){3}\z/.match?(identity)
      expected = numeric ? identity.split('.').map(&:to_i).pack('C4') : identity.downcase
      names.value.any? do |name|
        name.tag_class == :CONTEXT_SPECIFIC && name.value.instance_of?(String) &&
          (numeric ? name.tag == 7 && name.value == expected : name.tag == 2 && name.value.downcase == expected)
      end
    rescue OpenSSL::OpenSSLError, ArgumentError, TypeError, NoMethodError
      false
    end
  end
end
