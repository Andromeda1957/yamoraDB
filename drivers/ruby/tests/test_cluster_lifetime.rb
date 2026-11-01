# frozen_string_literal: true

require_relative 'cluster_helper'

class ClusterLifetimeTest < Minitest::Test
  include ClusterFixtures

  class DecodingClient < Yamora::ClusterClient
    def initialize(after_decode: nil, after_validation: nil, **options)
      @after_decode, @after_validation = after_decode, after_validation
      super(**options)
    end

    private

    def response_text(body)
      result = super
      @after_decode&.call
      result
    end

    def names?(value, limit)
      result = super
      @after_validation&.call
      result
    end

    def stored!(*args)
      result = super
      @after_validation&.call
      result
    end
  end

  def options(peer, pem, **extra)
    { seeds: [peer.seed], cluster_id: CLUSTER, voters: 3, tls: Yamora::TLS.new(ca_pem: pem['ca.pem']),
      read_token: READ_TOKEN, write_token: WRITE_TOKEN, timeout: 1, **extra }
  end

  def with_read_peer
    scratch do |dir|
      pem = certificates(dir)
      peer = TLSPeer.new(pem) do |socket, request|
        next if metadata(socket, request)
        path = request.first.split[1]
        case path
        when '/healthz'
          socket.write(reply('{"status":"ok"}'))
        when '/v1/collections/a/documents/b'
          if request.first.start_with?('PUT ')
            socket.write(reply(JSON.generate(stored), headers: { 'ETag' => %Q("#{ETAG}") }))
          else
            socket.write(reply("# exact\r\nn: 1\r\n", headers: { 'Content-Type' => 'application/yaml', 'ETag' => %Q("#{ETAG}") }))
          end
        when '/metrics'
          socket.write(reply("count 1\n", headers: { 'Content-Type' => 'text/plain' }))
        when '/v1/collections'
          socket.write(reply('{"collections":["a"]}'))
        else
          raise "unexpected fixture route #{path}"
        end
      end
      begin
        yield peer, pem
      ensure
        peer.close
      end
    end
  end

  def read_actions
    [[->(c) { c.health }, :after_decode], [->(c) { c.get('a', 'b') }, :after_decode],
     [->(c) { c.metrics }, :after_decode], [->(c) { c.collections }, :after_validation]]
  end

  def test_public_reads_check_deadline_after_json_raw_text_and_semantic_validation
    with_read_peer do |peer, pem|
      outcomes = read_actions.map do |run, stage|
        client = DecodingClient.new(**options(peer, pem, timeout: 0.05), stage => -> { sleep 0.08 })
        begin
          run.call(client)
          :returned_after_deadline
        rescue Yamora::Error => error
          [error.class, error.uncertain?]
        end
      end
      assert_equal Array.new(4) { [Yamora::DeadlineError, false] }, outcomes
    end
  end

  def test_public_reads_check_cancellation_after_json_raw_text_and_semantic_validation
    with_read_peer do |peer, pem|
      outcomes = read_actions.map do |run, stage|
        token = Yamora::Cancellation.new
        client = DecodingClient.new(**options(peer, pem), stage => -> { token.cancel! })
        begin
          client.with_request(cancellation: token) { |c| run.call(c) }
          :returned_after_cancellation
        rescue Yamora::Error => error
          [error.class, error.uncertain?]
        end
      end
      assert_equal Array.new(4) { [Yamora::CancelledError, false] }, outcomes
    end
  end

  def test_mutation_final_public_validation_preserves_generated_recovery_id
    with_read_peer do |peer, pem|
      outcomes = %i[deadline cancellation].map do |mode|
        token = Yamora::Cancellation.new
        callback = mode == :deadline ? -> { sleep 0.08 } : -> { token.cancel! }
        client = DecodingClient.new(**options(peer, pem, timeout: mode == :deadline ? 0.05 : 1), after_validation: callback)
        begin
          client.with_request(cancellation: token) { |c| c.put('a', 'b', 'n: 1') }
          :returned_outside_lifetime
        rescue Yamora::UncertainWriteError => error
          request = peer.requests.reverse.find { |r| r.first.start_with?('PUT ') }
          [error.request_id == request[1]['x-yamora-request-id'], error.reason]
        end
      end
      assert_equal [[true, 'Yamora::DeadlineError'], [true, 'Yamora::CancelledError']], outcomes
    end
  end

  def test_cancelling_suspended_write_fiber_does_not_interrupt_other_fiber
    with_read_peer do |peer, pem|
      token = Yamora::Cancellation.new
      writer = Yamora::ClusterClient.new(**options(peer, pem))
      transport = writer.instance_variable_get(:@transport)
      original = transport.method(:receipt!)
      transport.define_singleton_method(:receipt!) do |*args|
        Fiber.yield :receipt_pending
        original.call(*args)
      end
      first = Fiber.new do
        writer.with_request(cancellation: token) { |c| c.put('a', 'b', 'n: 1') }
      rescue Yamora::Error => error
        error
      end
      assert_equal :receipt_pending, first.resume
      reader = DecodingClient.new(**options(peer, pem), after_decode: -> { token.cancel! })
      second = Fiber.new do
        reader.health
      rescue Yamora::Error => error
        error
      end
      unrelated = second.resume
      cancelled = first.resume
      assert_kind_of Hash, unrelated, 'cancellation crossed from the suspended write into the unrelated read fiber'
      assert_equal 'ok', unrelated['status']
      assert_kind_of Yamora::UncertainWriteError, cancelled
      assert_equal 'Yamora::CancelledError', cancelled.reason
      request = peer.requests.find { |r| r.first.start_with?('PUT ') }
      assert_equal request[1]['x-yamora-request-id'], cancelled.request_id
    ensure
      first.resume if first&.alive?
    end
  end
end

class ClusterHandshakeCancellationTest < Minitest::Test
  include ClusterFixtures

  class ObservedCancellation < Yamora::Cancellation
    attr_reader :registrations, :peak_callbacks

    def initialize
      super
      @registrations, @peak_callbacks = 0, 0
    end

    def retained_callbacks = @mutex.synchronize { @callbacks.size }

    def register(*args, &callback)
      @registrations += 1
      super
    ensure
      @peak_callbacks = [@peak_callbacks, retained_callbacks].max
    end
  end

  class CancellingReconnect < ObservedCancellation
    def register(*args, &callback)
      ticket = super
      cancel! if registrations == 2
      ticket
    end
  end

  def test_cancellation_between_start_and_request_leaves_no_callback_after_reconnect_rejection
    scratch do |dir|
      pem = certificates(dir)
      peer = TLSPeer.new(pem) { |socket, _request| socket.write(reply) }
      transport = Yamora::Client.new(port: peer.port, tls: Yamora::TLS.new(ca_pem: pem['ca.pem'])).instance_variable_get(:@transport)
      outcomes = 3.times.map do
        token = ObservedCancellation.new
        error = assert_raises(Yamora::CancelledError) do
          transport.request('GET', '/healthz', cancellation: token, on_dispatch: -> { token.cancel! })
        end
        [error.uncertain?, token.registrations, token.retained_callbacks]
      end
      assert_empty peer.requests, 'cancelled reconnect transmitted an HTTP request'
      assert_equal Array.new(3) { [false, 2, 0] }, outcomes
    ensure
      peer&.close
    end
  end

  def test_closed_idle_and_eof_reconnects_keep_only_one_callback_until_release
    scratch do |dir|
      pem = certificates(dir)
      closed = Queue.new
      peer = TLSPeer.new(pem) do |socket, _request|
        socket.write(reply)
        socket.close
        closed << true
      end
      outcomes = %i[closed idle eof].map do |mode|
        token = ObservedCancellation.new
        http = Yamora.const_get(:BoundedHTTP).new('127.0.0.1', peer.port, nil)
        http.cancellation = token
        http.max_retries = 0
        Yamora::TLS.new(ca_pem: pem['ca.pem']).configure(http)
        Timeout.timeout(2) do
          http.start do
            assert_equal '{}', http.request(Net::HTTP::Get.new('/healthz')).body
            closed.pop
            case mode
            when :closed then http.instance_variable_get(:@socket).close
            when :idle then http.keep_alive_timeout = 0
            when :eof
              assert http.instance_variable_get(:@socket).io.to_io.wait_readable(1), 'peer EOF was not ready'
            end
            assert_equal '{}', http.request(Net::HTTP::Get.new('/healthz')).body
            closed.pop
          end
        end
        http.release_cancellation
        [mode, token.registrations, token.peak_callbacks, token.retained_callbacks]
      ensure
        http&.finish if http&.started?
        http&.release_cancellation
      end
      assert_equal %i[closed idle eof].map { |mode| [mode, 2, 1, 0] }, outcomes
    ensure
      peer&.close
    end
  end

  def test_cancellation_during_replacement_registration_closes_new_unpublished_socket
    scratch do |dir|
      pem = certificates(dir)
      peer = TLSPeer.new(pem) { |socket, _request| socket.write(reply) }
      token = CancellingReconnect.new
      http = Yamora.const_get(:BoundedHTTP).new('127.0.0.1', peer.port, nil)
      http.cancellation = token
      http.max_retries = 0
      Yamora::TLS.new(ca_pem: pem['ca.pem']).configure(http)
      outcome = Timeout.timeout(2) do
        http.start do
          http.instance_variable_get(:@socket).close
          begin
            http.request(Net::HTTP::Get.new('/healthz'))
            :returned
          rescue IOError, SystemCallError, OpenSSL::OpenSSLError
            :interrupted
          end
        end
      end
      http.release_cancellation
      assert_equal [:interrupted, 2, 0, 0], [outcome, token.registrations, token.retained_callbacks, peer.requests.size]
    ensure
      http&.finish if http&.started?
      http&.release_cancellation
      peer&.close
    end
  end

  class InterruptedRegistration < Yamora::Cancellation
    attr_reader :installed, :invocations

    def initialize
      super
      @installed, @invocations = Queue.new, Queue.new
    end

    def register(*args, &callback)
      ticket = super(*args) { @invocations << :closed; callback.call }
      @installed << true
      # The controller raises Timeout::Error asynchronously here, after the
      # token owns the callback but before the transport can receive a ticket.
      Queue.new.pop
      ticket
    end
  end

  def test_async_timeout_after_callback_installation_releases_reused_token_and_socket
    listener = TCPServer.new('127.0.0.1', 0)
    port = listener.addr[1]
    raise 'owner port allocated' if port == 8000
    token = InterruptedRegistration.new
    transport = Yamora::Client.new(port: port, tls: Yamora::TLS.new, timeout: 3).instance_variable_get(:@transport)
    3.times do
      worker = Thread.new do
        transport.request('GET', '/healthz', cancellation: token)
      rescue Yamora::Error => error
        error
      end
      socket = Timeout.timeout(1) { listener.accept }
      Timeout.timeout(1) { token.installed.pop }
      worker.raise Timeout::Error, 'injected at installed callback boundary'
      assert worker.join(0.5), 'interrupted transport did not unwind'
      assert_instance_of Yamora::TransportError, worker.value
      refute token.cancelled?, 'a timeout must leave the token reusable'
      assert_empty Timeout.timeout(0.5) { socket.read }, 'owned raw connection survived the timeout'
    ensure
      socket&.close unless socket&.closed?
      worker&.kill&.join if worker&.alive?
    end
    token.cancel!
    assert_equal 0, token.invocations.size, 'the reusable token retained callbacks from interrupted transports'
  ensure
    listener&.close
  end

  def test_stalled_tls_cancellation_closes_only_owned_unpublished_socket_without_gc
    listener = TCPServer.new('127.0.0.1', 0)
    port = listener.addr[1]
    raise 'owner port allocated' if port == 8000
    client = Yamora::ClusterClient.new(seeds: [{ host: '127.0.0.1', port: port, node: 1 }],
                cluster_id: CLUSTER, voters: 3, tls: Yamora::TLS.new, timeout: 2, attempt_timeout: 2)
    # Initialize Timeout's scheduler before measuring owned descriptors.
    begin
      Timeout.timeout(0.001) { sleep 0.01 }
    rescue Timeout::Error
      nil
    end
    GC.start
    previously_disabled = GC.disable
    baseline = Dir.children('/proc/self/fd').size if Dir.exist?('/proc/self/fd')
    3.times do
      token, result = Yamora::Cancellation.new, Queue.new
      worker = Thread.new do
        client.with_request(cancellation: token) { |c| c.health }
      rescue Yamora::Error => error
        result << error
      end
      socket = Timeout.timeout(1) { listener.accept }
      hello = Timeout.timeout(1) { socket.readpartial(1) }
      refute_empty hello
      token.cancel!
      assert worker.join(0.5), 'cancellation waited for the stalled TLS attempt deadline'
      error = result.pop
      assert_instance_of Yamora::CancelledError, error
      refute error.uncertain?
      Timeout.timeout(0.5) { socket.read } # EOF must arrive before GC or teardown.
      socket.close
      assert_equal baseline, Dir.children('/proc/self/fd').size if baseline
    ensure
      socket&.close unless socket&.closed?
      worker&.kill&.join if worker&.alive?
    end
  ensure
    listener&.close
    GC.enable unless previously_disabled
  end
end
