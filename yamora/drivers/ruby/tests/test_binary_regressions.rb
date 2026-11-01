# frozen_string_literal: true

require_relative 'binary_helper'

class BinaryRegressionTest < Minitest::Test
  include BinaryFixtures

  def test_bounded_source_snapshot
    source, commands, mutated = SOURCE.dup, Queue.new, Queue.new
    replacement = 'x' * (Yamora::MAX_DOCUMENT_BYTES + 1)
    mutator = Thread.new do
      source.replace(replacement) if commands.pop == :grow
      mutated << true
    end
    fired = false
    # Coordinate a real second thread at the C operation's return boundary.
    # Old code returns a caller size before copying; fixed code returns an
    # already bounded, owned byteslice. No caller methods are overridden.
    trace = TracePoint.new(:c_return) do |event|
      next if fired || !event.self.equal?(source) || !%i[bytesize byteslice].include?(event.method_id)
      fired = true
      commands << :grow
      await(mutated)
      puts 'SNAPSHOT:bounded_source_snapshot'
    end
    begin
      envelope = trace.enable(target_thread: Thread.current) do
        Yamora::BinaryEnvelope.new(method: 'PUT', collection: 'c', document: 'd', source: source)
      end
      assert fired, 'race barrier must observe the core caller-string operation'
      assert_operator envelope.source.bytesize, :<=, Yamora::MAX_DOCUMENT_BYTES, 'GUARD:bounded_source_snapshot'
      assert_equal SOURCE.b, envelope.source
      assert envelope.source.frozen?
      assert_equal Yamora::MAX_DOCUMENT_BYTES + 1, source.bytesize
    ensure
      trace.disable
      commands << :stop
      join_owners([mutator])
    end
  end

  def rejected_conditional_304(method, name)
    peer_test(->(socket, request, _) do
      puts "DISPATCH:#{name}"
      fields, = response_parts(request, status: 304, body: ''.b,
                               changes: { 4 => [SOURCE.bytesize].pack('Q>') })
      # Valid RESPONSE + END, zero wire DATA, positive representation length.
      socket.write(bin_frame(3, 1, bin_fields(fields)) + bin_frame(5, 1))
    end) do |client, peer|
      error = assert_raises(Yamora::BinaryError, "GUARD:#{name}") do
        client.request(method, 'c', 'd', if_none_match: '"0000000000000000"', request_id: ID)
      end
      assert_equal :protocol, error.kind
      refute error.uncertain?
      assert_equal 1, peer.requests.size
    end
  end

  def test_head_304_condition = rejected_conditional_304('HEAD', 'head_304_condition')
  def test_get_304_condition = rejected_conditional_304('GET', 'get_304_condition')

  def test_missing_receipt_id
    peer_test(->(socket, request, _) do
      puts 'DISPATCH:missing_receipt_id'
      send_response(socket, request, changes: { 12 => nil })
    end) do |client, peer|
      error = assert_raises(Yamora::BinaryUncertainWriteError, 'GUARD:missing_receipt_id') do
        client.put('c', 'd', SOURCE, request_id: ID)
      end
      assert_equal :protocol, error.kind
      assert_equal 1, peer.requests.size
      assert_equal ID, error.envelope.request_id
    end
  end

  def test_get_source_hash
    peer_test(->(socket, request, _) do
      puts 'DISPATCH:get_source_hash'
      send_response(socket, request, changes: { 6 => '"0000000000000000"' })
    end) do |client, peer|
      error = assert_raises(Yamora::BinaryError, 'GUARD:get_source_hash') { client.get('c', 'd') }
      assert_equal :protocol, error.kind
      assert_equal 1, peer.requests.size
    end
  end

  def test_create_only_status
    peer_test(->(socket, request, _) do
      puts 'DISPATCH:create_only_status'
      send_response(socket, request, status: 200)
    end) do |client, peer|
      error = assert_raises(Yamora::BinaryUncertainWriteError, 'GUARD:create_only_status') { client.put('c', 'd', SOURCE, if_none_match: '*') }
      assert_equal :protocol, error.kind
      assert_equal 1, peer.requests.size
    end
  end

  def test_incomplete_body_at_end
    peer_test(->(socket, request, _) do
      puts 'DISPATCH:incomplete_body_at_end'
      fields, body = response_parts(request)
      fields[3] = fields[4] = [body.bytesize + 1].pack('Q>')
      socket.write(bin_frame(3, 1, bin_fields(fields)) + bin_frame(4, 1, body) + bin_frame(5, 1))
    end) do |client, peer|
      error = assert_raises(Yamora::BinaryUncertainWriteError, 'GUARD:incomplete_body_at_end') { client.put('c', 'd', SOURCE) }
      assert_equal :protocol, error.kind
      assert_equal 1, peer.requests.size
    end
  end

  def test_missing_end
    peer_test(->(socket, request, _) do
      puts 'DISPATCH:missing_end'
      fields, body = response_parts(request)
      socket.write(bin_frame(3, 1, bin_fields(fields)) + bin_frame(4, 1, body))
    end) do |client, peer|
      error = assert_raises(Yamora::BinaryUncertainWriteError, 'GUARD:missing_end') { client.put('c', 'd', SOURCE) }
      assert_equal :transport, error.kind
      assert_equal 1, peer.requests.size
    end
  end

  def test_immutable_uncertainty_envelope
    peer_test(->(socket, _, _) do
      puts 'DISPATCH:immutable_uncertainty_envelope'
      socket.write(bin_frame(7, 1, [1].pack('N')))
    end) do |client, peer|
      outcome = begin
        client.put('c', 'd', SOURCE, request_id: ID)
      rescue Yamora::BinaryError => error
        error
      end
      assert_instance_of Yamora::BinaryUncertainWriteError, outcome, 'GUARD:immutable_uncertainty_envelope'
      assert_equal ID, outcome.envelope.request_id
      assert_equal SOURCE.b, outcome.envelope.source
      assert_equal 1, peer.requests.size
    end
  end
end
