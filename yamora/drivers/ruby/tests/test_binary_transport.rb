# frozen_string_literal: true

require_relative 'binary_helper'

class BinaryTransportTest < Minitest::Test
  include BinaryFixtures

  def test_get_head_304_requires_matching_condition_and_complete_bodyless_end
    %w[GET HEAD].each do |method|
      [native_etag(SOURCE), '*'].each do |condition|
        peer_test(->(socket, request, _) do
          fields, = response_parts(request, status: 304, body: ''.b,
                                   changes: { 4 => [SOURCE.bytesize].pack('Q>') })
          socket.write(bin_frame(3, 1, bin_fields(fields)) + bin_frame(5, 1))
        end) do |client, peer|
          response = client.request(method, 'c', 'd', if_none_match: condition, request_id: ID)
          assert_equal 304, response.status
          assert_equal 0, response.body_length
          assert_equal SOURCE.bytesize, response.representation_length
          assert_equal native_etag(SOURCE), response.etag
          assert_equal ID, response.request_id
          assert_empty response.body
          assert_equal 1, peer.requests.size
        end
      end
      [nil, ''].each do |condition|
        peer_test(->(socket, request, _) do
          fields, = response_parts(request, status: 304, body: ''.b,
                                   changes: { 4 => [SOURCE.bytesize].pack('Q>') })
          socket.write(bin_frame(3, 1, bin_fields(fields)) + bin_frame(5, 1))
        end) do |client, peer|
          binary_failure(:protocol) { client.request(method, 'c', 'd', if_none_match: condition) }
          assert_equal 1, peer.requests.size
        end
      end
    end
  end

  def test_get_head_304_rejects_data_nonzero_wire_length_and_missing_end
    %w[GET HEAD].each do |method|
      %i[data wire_length missing_end].each do |fault|
        peer_test(->(socket, request, _) do
          fields, = response_parts(request, status: 304, body: ''.b,
                                   changes: { 4 => [SOURCE.bytesize].pack('Q>') })
          fields[3] = [SOURCE.bytesize].pack('Q>') if fault == :wire_length
          frames = bin_frame(3, 1, bin_fields(fields))
          frames << bin_frame(4, 1, SOURCE.b) if fault == :data
          frames << bin_frame(5, 1) unless fault == :missing_end
          socket.write(frames)
        end) do |client, peer|
          binary_failure(fault == :missing_end ? :transport : :protocol) do
            client.request(method, 'c', 'd', if_none_match: '*')
          end
          assert_equal 1, peer.requests.size
        end
      end
    end
  end

  def test_fragmented_crud_immutable_bodies_per_call_bearer_and_ids
    peer_test(->(socket, request, _) { send_response(socket, request, fragment: true) }) do |client, peer|
      source, token, id = SOURCE.dup, WRITE_TOKEN.dup, ID.dup
      result = client.put('c', 'd', source, token: token, request_id: id, if_none_match: '*')
      source.replace('modified'); token.replace('credential-modified'); id.replace('f' * 32)
      assert_equal 201, result.status
      assert_equal ID, result.request_id
      assert_equal SOURCE.b, peer.requests.first[:source]
      assert_equal 'Bearer ' + WRITE_TOKEN, peer.requests.first[:fields][5]
      assert_equal result.etag, native_etag(SOURCE)
      assert result.body.frozen?
      assert_raises(FrozenError) { result.body.replace('bad') }
      read = client.get('c', 'd', token: READ_TOKEN)
      assert_equal SOURCE.b, read.body.b
      assert_nil read.request_id
      head = client.head('c', 'd', token: READ_TOKEN)
      assert_empty head.body
      assert_equal SOURCE.bytesize, head.representation_length
      removed = client.delete('c', 'd', token: WRITE_TOKEN)
      assert_equal 204, removed.status
      refute_equal '0' * 32, removed.request_id
      assert_equal 32, removed.request_id.size
      assert_equal 4, peer.requests.size
      refute_includes client.inspect, WRITE_TOKEN
      refute_includes result.inspect, SOURCE
    end
  end

  def test_dispatched_ambiguous_outcomes_retain_exact_immutable_envelope_without_replay
    cases = {
      eof: ->(_socket, _request) {},
      partial_header: ->(socket, _) { socket.write(bin_frame(3, 1, 'metadata').byteslice(0, 10)) },
      error_one: ->(socket, _) { socket.write(bin_frame(7, 1, [1].pack('N'))) },
      error_zero: ->(socket, _) { socket.write(bin_frame(7, 1, [0].pack('N'))) },
      goaway: ->(socket, _) { socket.write(bin_frame(10, 0)) },
      missing_end: ->(socket, request) { fields, body = response_parts(request); socket.write(bin_frame(3, 1, bin_fields(fields)) + bin_frame(4, 1, body)) },
      partial_data: ->(socket, request) { fields, body = response_parts(request); socket.write(bin_frame(3, 1, bin_fields(fields)) + bin_frame(4, 1, body).byteslice(0...-1)) },
      too_few_data: ->(socket, request) { fields, body = response_parts(request); socket.write(bin_frame(3, 1, bin_fields(fields)) + bin_frame(4, 1, body.byteslice(0...-1)) + bin_frame(5, 1)) },
      response_500: ->(socket, request) { send_response(socket, request, status: 500) },
      response_408: ->(socket, request) { send_response(socket, request, status: 408) }
    }
    cases.each do |label, behavior|
      peer_test(->(socket, request, _) { behavior.call(socket, request) }) do |client, peer|
        error = assert_raises(Yamora::BinaryUncertainWriteError, label.to_s) do
          client.put('c', 'd', SOURCE, token: WRITE_TOKEN, request_id: ID, if_match: '"0123456789abcdef"', if_none_match: '')
        end
        assert error.uncertain?
        assert_equal 1, peer.requests.size, "#{label}: request must dispatch exactly once"
        envelope = error.envelope
        assert_equal ID, envelope.request_id
        assert_equal SOURCE.b, envelope.source
        assert_equal '"0123456789abcdef"', envelope.if_match
        assert_equal '', envelope.if_none_match
        assert_equal '/v1/collections/c/documents/d', envelope.target
        assert_equal 'application/yaml', envelope.content_type
        assert envelope.frozen?
        refute envelope.respond_to?(:token)
        refute_includes error.full_message, WRITE_TOKEN
        assert_nil error.cause
      end
    end
  end

  def test_semantic_receipt_id_status_and_hash_failures_are_uncertain_after_dispatch
    changes = {
      missing_id: { 12 => nil }, wrong_id: { 12 => ['e' * 32].pack('H*') }, zero_id: { 12 => "\0" * 16 },
      wrong_revision: { 5 => 'a' * 16 }, wrong_target: { 8 => 'another' }, wrong_hash: { 6 => '"0000000000000000"' },
      bad_etag: { 6 => '"GGGGGGGGGGGGGGGG"' }, wrong_type: { 2 => 'text/plain' }, bad_allow: { 9 => [1].pack('C') },
      bad_auth: { 10 => [1].pack('C') }, bad_retry: { 11 => [0].pack('N') }, oversized_ack: { 3 => [4097].pack('Q>'), 4 => [4097].pack('Q>') }
    }
    changes.each do |label, metadata_changes|
      peer_test(->(socket, request, _) { send_response(socket, request, changes: metadata_changes) }) do |client, peer|
        binary_failure(:protocol, uncertain: true) { client.put('c', 'd', SOURCE, token: WRITE_TOKEN, request_id: ID) }
        assert_equal 1, peer.requests.size, "#{label}: confirmed dispatch"
      end
    end
    peer_test(->(socket, request, _) { send_response(socket, request, status: 200) }) do |client, peer|
      binary_failure(:protocol, uncertain: true) { client.put('c', 'd', SOURCE, if_none_match: '*') }
      assert_equal 1, peer.requests.size
    end
    peer_test(->(socket, request, _) { send_response(socket, request, status: 201) }) do |client, peer|
      binary_failure(:protocol, uncertain: true) { client.put('c', 'd', SOURCE, if_match: '"0123456789abcdef"') }
      assert_equal 1, peer.requests.size
    end
    bad_bodies = ['{"status":"stored","status":"stored"}', '{"status":true}', "{\"s\":\"\xff\"}".b, '{"n":1e999}']
    bad_bodies.each do |body|
      peer_test(->(socket, request, _) { send_response(socket, request, body: body) }) do |client, peer|
        binary_failure(:protocol, uncertain: true) { client.put('c', 'd', SOURCE) }
        assert_equal 1, peer.requests.size
      end
    end
  end

  def test_get_identity_head_body_delete_and_unrequested_ids_are_rejected
    peer_test(->(socket, request, _) { send_response(socket, request, changes: { 6 => '"0000000000000000"' }) }) do |client, peer|
      binary_failure(:protocol) { client.get('c', 'd') }
      assert_equal 1, peer.requests.size
    end
    peer_test(->(socket, request, _) { send_response(socket, request, changes: { 12 => [ID].pack('H*') }) }) do |client, peer|
      binary_failure(:protocol) { client.get('c', 'd') }
      assert_equal 1, peer.requests.size
    end
    peer_test(->(socket, request, _) { send_response(socket, request, body: 'unexpected') }) do |client, peer|
      binary_failure(:protocol) { client.head('c', 'd') }
      assert_equal 1, peer.requests.size
    end
    peer_test(->(socket, request, _) { send_response(socket, request, status: 200) }) do |client, peer|
      binary_failure(:protocol, uncertain: true) { client.delete('c', 'd') }
      assert_equal 1, peer.requests.size
    end
    peer_test(->(socket, request, _) { send_response(socket, request, source: "v: \xff".b) }) do |client, peer|
      binary_failure(:protocol) { client.get('c', 'd') }
      assert_equal 1, peer.requests.size
    end
  end

  def test_correctly_framed_rejections_are_definite_only_after_valid_end_and_json
    [400, 401, 403, 404, 409, 412, 413, 429].each do |status|
      peer_test(->(socket, request, _) { send_response(socket, request, status: status) }) do |client, peer|
        error = assert_raises(Yamora::BinaryStatusError) { client.put('c', 'd', SOURCE) }
        assert_equal status, error.status
        refute error.uncertain?
        assert_equal 1, peer.requests.size
      end
    end
    peer_test(->(socket, request, _) { send_response(socket, request, status: 401, body: '{"k":1,"k":2}') }) do |client, peer|
      binary_failure(:protocol, uncertain: true) { client.put('c', 'd', SOURCE) }
      assert_equal 1, peer.requests.size
    end
  end

  def test_hostile_frame_lengths_and_order_fail_before_waiting_for_payload
    headers = [[3, 1, 2049], [4, 1, 65_537], [4, 2, 4], [5, 1, 1], [8, 0, 9], [11, 1, 0], [1, 0, 12]]
    headers.each do |kind, stream, size|
      peer_test(->(socket, _, _) do
        socket.write(['YMBF', 1, kind, 0, stream, size].pack('a4CCnNN'))
        socket.write([1, 1, 4096, 1].pack('nnNN')) if kind == 1
        sleep 0.15
      end) do |client, peer|
        error = binary_failure(:protocol, uncertain: true) { client.put('c', 'd', SOURCE, timeout: 0.5) }
        assert_equal SOURCE.b, error.envelope.source
        assert_equal 1, peer.requests.size
      end
    end
    peer_test(->(socket, _, _) { socket.write(bin_frame(4, 1, 'early')) }) do |client, peer|
      binary_failure(:protocol) { client.get('c', 'd') }
      assert_equal 1, peer.requests.size
    end
  end

  def test_control_ping_echo_and_bounded_control_flood
    peer_test(->(socket, request, _) do
      socket.write(bin_frame(8, 0, 'abcdefgh'))
      raise 'PONG mismatch' unless bin_read(socket) == [9, 0, 'abcdefgh']
      send_response(socket, request)
    end) do |client, peer|
      assert_equal SOURCE.b, client.get('c', 'd').body.b
      assert_equal 1, peer.requests.size
    end
    peer_test(->(socket, _, _) do
      17.times do
        socket.write(bin_frame(8, 0, 'abcdefgh'))
        bin_read(socket) if _1 < 16
      end
    end) do |client, peer|
      binary_failure(:protocol, uncertain: true) { client.put('c', 'd', SOURCE) }
      assert_equal 1, peer.requests.size
    end
  end

  def test_one_deadline_across_slow_drip_fragments_and_no_automatic_reconnect
    peer_test(->(socket, request, _) do
      fields, body = response_parts(request)
      socket.write(bin_frame(3, 1, bin_fields(fields)))
      body.bytes.each_slice(10) do |part|
        sleep 0.04
        socket.write(bin_frame(4, 1, part.pack('C*')))
      end
      socket.write(bin_frame(5, 1))
    end, peer_options: { handshake_failure: true }) do |client, peer|
      error = binary_failure(:timeout, uncertain: true) { client.put('c', 'd', SOURCE, timeout: 0.15, request_id: ID) }
      assert_equal ID, error.envelope.request_id
      assert_equal 1, peer.requests.size
    end
  end

  def test_tls_failure_identity_and_frozen_trust
    [nil, 'http/1.1'].each do |alpn|
      peer_test(->(_socket, _, _) { flunk 'request dispatched without binary ALPN' },
                peer_options: { alpn: alpn, handshake_failure: true }) do |client, peer|
        binary_failure(alpn.nil? ? :protocol : :tls) { client.put('c', 'd', SOURCE) }
        assert_empty peer.requests
      end
    end
    peer_test(->(*) { flunk 'TLS1.2 dispatched' }, peer_options: { version: OpenSSL::SSL::TLS1_2_VERSION, handshake_failure: true }) do |client, peer|
      binary_failure(:tls) { client.put('c', 'd', SOURCE) }
      assert_empty peer.requests
    end
    peer_test(->(socket, request, _) { send_response(socket, request) }) do |client, peer, pem|
      pem.each_value { |bytes| bytes.replace('caller erased TLS material') }
      assert_equal SOURCE.b, client.get('c', 'd').body.b
      assert_equal 1, peer.requests.size
    end
  end

  def test_four_admitted_owners_waiter_deadline_and_freeze_only_after_admission
    entered, releases = Queue.new, Queue.new
    handler = ->(socket, request, _) do
      entered << request
      releases.pop if request[:fields][2].end_with?('/held')
      send_response(socket, request)
    end
    peer_test(handler, config_options: { concurrency: 4 }) do |client, peer|
      owners = []
      errors = Queue.new
      begin
        4.times { owners << Thread.new { client.get('c', 'held') rescue errors << $! } }
        4.times { await(entered) }
        # Even invalid source/name is untouched while admission is full.
        binary_failure(:timeout) { client.put('invalid/name', 'd', Object.new, timeout: 0.05) }
        cancellation = Yamora::BinaryCancellation.new
        cancellation.cancel
        binary_failure(:cancelled) { client.put('c', 'd', SOURCE, cancel: cancellation) }
        assert_equal 4, peer.requests.size
        source = "\xff".b
        waiting = Queue.new
        owners << Thread.new do
          waiting << true
          client.put('c', 'late', source)
        rescue StandardError => error
          errors << error
        end
        await(waiting)
        sleep 0.03
        source.replace(SOURCE)
        4.times { releases << true }
        observed = await(entered)
        assert_equal SOURCE.b, observed[:source], 'waiting input must be frozen after admission'
        join_owners(owners)
        assert errors.empty?, "owner failed: #{errors.pop unless errors.empty?}"
        assert_equal 5, peer.requests.size
      ensure
        4.times { releases << true }
        client.close
        join_owners(owners)
      end
    end
  end

  def test_cancelled_owner_cannot_interrupt_other_call_and_close_joins_owners
    entered, releases = Queue.new, Queue.new
    handler = ->(socket, request, _) do
      entered << request
      releases.pop
      send_response(socket, request)
    end
    peer_test(handler, peer_options: { handshake_failure: true }, config_options: { concurrency: 2 }) do |client, peer|
      cancelled = Yamora::BinaryCancellation.new
      outcomes, owners = Queue.new, []
      begin
        owners << Thread.new do
          client.put('c', 'cancelled', SOURCE, request_id: ID, cancel: cancelled)
        rescue StandardError => error
          outcomes << error
        end
        await(entered)
        owners << Thread.new { outcomes << client.get('c', 'neighbor') rescue outcomes << $! }
        await(entered)
        cancelled.cancel
        error = await(outcomes)
        assert_instance_of Yamora::BinaryUncertainWriteError, error
        assert_equal :cancelled, error.kind
        assert_equal ID, error.envelope.request_id
        2.times { releases << true }
        result = await(outcomes)
        assert_instance_of Yamora::BinaryResponse, result
        assert_equal SOURCE.b, result.body.b
        join_owners(owners)
        assert_equal 2, peer.requests.size
        owners << Thread.new { client.get('c', 'closing') rescue outcomes << $! }
        await(entered)
        client.close
        error = await(outcomes)
        assert_equal :closed, error.kind
        refute error.uncertain?
        assert owners.last.join(1)
        binary_failure(:closed) { client.get('c', 'd') }
      ensure
        3.times { releases << true }
        cancelled.cancel
        client.close
        join_owners(owners)
      end
    end
  end

  def test_concurrent_callers_cannot_mutate_dispatched_envelopes_or_other_owners
    entered, releases = Queue.new, Queue.new
    peer_test(->(socket, request, _) do
      entered << request
      releases.pop
      socket.write(bin_frame(7, 1, [1].pack('N')))
    end, config_options: { concurrency: 3 }) do |client, peer|
      inputs = 3.times.map do |index|
        { source: SOURCE.dup, token: WRITE_TOKEN.dup, id: format('%032x', index + 1),
          collection: +'c', document: "d#{index}", condition: +'"0123456789abcdef"' }
      end
      outcomes, owners = Queue.new, []
      begin
        inputs.each do |input|
          owners << Thread.new do
            client.put(input[:collection], input[:document], input[:source], token: input[:token],
                       request_id: input[:id], if_match: input[:condition])
          rescue StandardError => error
            outcomes << error
          end
        end
        3.times { await(entered) }
        inputs.each { |input| input.each_value { |value| value.replace('caller overwrote bytes') } }
        3.times { releases << true }
        errors = 3.times.map { await(outcomes) }.sort_by { |error| error.envelope.request_id }
        errors.each_with_index do |error, index|
          assert_instance_of Yamora::BinaryUncertainWriteError, error
          assert_equal format('%032x', index + 1), error.envelope.request_id
          assert_equal "d#{index}", error.envelope.document
          assert_equal SOURCE.b, error.envelope.source
          assert_equal '"0123456789abcdef"', error.envelope.if_match
          assert error.envelope.source.frozen?
          refute_includes error.full_message, WRITE_TOKEN
        end
        assert_equal 3, peer.requests.size
        assert peer.requests.all? { |request| request[:fields][5] == 'Bearer ' + WRITE_TOKEN && request[:source] == SOURCE.b }
      ensure
        3.times { releases << true }
        client.close
        join_owners(owners)
      end
    end
  end
end
