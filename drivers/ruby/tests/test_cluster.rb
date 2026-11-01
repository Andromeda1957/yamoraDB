# frozen_string_literal: true

require_relative 'cluster_helper'

class ClusterTest < Minitest::Test
  include ClusterFixtures

  def test_configuration_is_pinned_private_verified_and_redacted
    scratch do |dir|
      pem = certificates(dir)
      valid = { seeds: [{ host: '127.0.0.1', port: 8765, node: 1 }], cluster_id: CLUSTER, voters: 3,
                tls: Yamora::TLS.new(ca_pem: pem['ca.pem']), write_token: WRITE_TOKEN }
      [{ seeds: [] }, { seeds: valid[:seeds] * 2 }, { tls: nil }, { voters: 2 }, { voters: 11 },
       { cluster_id: '0' * 32 }, { seeds: [{ host: 'localhost', port: 8765, node: 1 }] },
       { seeds: [{ host: '8.8.8.8', port: 8765, node: 1 }] }, { seeds: [{ host: '127.0.0.1', port: 8765, node: 4 }] },
       { seeds: [{ host: '127.0.0.1', port: 8765 }] }, { timeout: 0 }, { attempt_timeout: 31 }].each do |bad|
        assert_raises(ArgumentError) { Yamora::ClusterClient.new(**valid, **bad) }
      end
      client = Yamora::ClusterClient.new(**valid)
      assert_kind_of Yamora::Client, client
      refute_includes client.inspect, WRITE_TOKEN
    end
  end

  def test_exact_yaml_conditions_and_identity_are_owned_before_discovery_and_retry
    scratch do |dir|
      pem = certificates(dir)
      source, etag, id = +"# exact café\r\nn: 1\r\n", +ETAG, +('1' * 32)
      first = TLSPeer.new(pem) do |socket, request|
        if metadata(socket, request)
          source.replace('changed'); etag.replace('0' * 16); id.replace('2' * 32)
        end
        # Fully read mutation, then lose the reply.
      end
      second = TLSPeer.new(pem) do |socket, request|
        next if metadata(socket, request, node: 2)
        socket.write(reply(JSON.generate(stored), headers: { 'ETag' => %Q("#{ETAG}") }))
      end
      begin
        client = cluster_client([first.seed, second.seed(2)], pem)
        assert_equal stored, client.put('a', 'b', source, etag: etag, request_id: id)
        writes = [first, second].map { |peer| peer.requests.find { |r| r.first.start_with?('PUT ') } }
        assert writes.all?
        writes.each do |request|
          assert_equal "# exact café\r\nn: 1\r\n".b, request[2]
          assert_equal %Q("#{ETAG}"), request[1]['if-match']
          assert_equal '1' * 32, request[1]['x-yamora-request-id']
          assert_equal "Bearer #{WRITE_TOKEN}", request[1]['authorization']
        end
        assert_equal writes.first[2], writes.last[2]
      ensure
        first.close; second.close
      end
    end
  end
end

class ClusterHostileTest < Minitest::Test
  include ClusterFixtures

  def test_every_dispatched_bad_receipt_keeps_generated_id_and_sanitized_uncertainty
    scratch do |dir|
      pem = certificates(dir)
      cases = [
        [:put, ->(c) { c.put('a', 'b', 'n: 1') }, stored],
        [:patch, ->(c) { c.patch('a', 'b', { '$inc' => { 'n' => 1 } }) }, stored],
        [:transaction, ->(c) { c.transaction([{ 'collection' => 'a', 'document' => 'b', 'delete' => true }]) }, { 'status' => 'committed', 'operations' => 1, 'revision' => REV }],
        [:catalog, ->(c) { c.set_indexes([]) }, { 'status' => 'committed', 'operations' => 1, 'revision' => REV }],
        [:delete, ->(c) { c.delete('a', 'b') }, nil]
      ]
      cases.each do |name, run, good|
        variants = %i[json truncated duplicate transfer revision status http500 semantic etag nonfinite]
        variants += %i[count_float count_zero] if %i[catalog transaction].include?(name)
        variants.each do |variant|
          id = nil
          peer = TLSPeer.new(pem) do |socket, request|
            next if metadata(socket, request)
            id = request[1]['x-yamora-request-id']
            value = good&.dup
            value['status'] = 'failed' if variant == :semantic && value
            value['operations'] = variant == :count_float ? 1.0 : 0 if %i[count_float count_zero].include?(variant)
            body = value ? JSON.generate(value) : ''
            headers = { 'ETag' => %Q("#{ETAG}") }
            status = name == :delete ? 204 : 200
            case variant
            when :json then body = '{bad'
            when :nonfinite then body = body.sub(/}\z/, ',"extra":1e400}')
            when :truncated then headers['Content-Length'] = (body.bytesize + 100).to_s
            when :duplicate then headers['x-yamldb-revision'] = REV
            when :transfer then headers['Transfer-Encoding'] = 'chunked'
            when :revision then headers['X-YamlDB-Revision'] = 'fedcba9876543210'
            when :status then status = 202
            when :http500 then status = 500; body = READ_TOKEN
            when :etag then headers['ETag'] = '"0000000000000000"'
            end
            # For DELETE all variants must actually break its own receipt contract.
            if name == :delete && %i[json semantic etag revision nonfinite].include?(variant)
              headers['X-YamlDB-Revision'] = 'invalid'
            end
            socket.write(reply(body, status: status, headers: headers))
          end
          begin
            error = assert_raises(Yamora::UncertainWriteError, "#{name}/#{variant}") { run.call(cluster_client([peer], pem)) }
            assert error.uncertain?, "#{name}/#{variant}"
            assert_equal id, error.request_id
            assert_match(/\A[0-9a-f]{32}\z/, id)
            assert_nil error.cause
            refute_includes error.inspect, READ_TOKEN
            refute_includes error.inspect, WRITE_TOKEN
          ensure
            peer.close
          end
        end
      end
    end
  end

  def test_definitive_rejection_changes_to_uncertain_only_after_earlier_dispatch
    scratch do |dir|
      pem = certificates(dir)
      first = TLSPeer.new(pem) do |socket, request|
        next if metadata(socket, request)
        socket.write(reply('', status: 503))
      end
      second = TLSPeer.new(pem) do |socket, request|
        next if metadata(socket, request, node: 2)
        socket.write(reply(WRITE_TOKEN, status: 412))
      end
      begin
        client = cluster_client([second.seed(2)], pem)
        error = assert_raises(Yamora::HTTPError) { client.put('a', 'b', 'n: 1') }
        assert_equal 412, error.status
        refute error.uncertain?
        client = cluster_client([first.seed, second.seed(2)], pem)
        error = assert_raises(Yamora::UncertainWriteError) { client.put('a', 'b', 'n: 1', request_id: '3' * 32) }
        assert_equal 412, error.status
        assert_equal '3' * 32, error.request_id
      ensure
        first.close; second.close
      end
    end
  end

  def test_wrong_node_cluster_voters_and_redirects_never_receive_write_credentials
    scratch do |dir|
      pem = certificates(dir)
      trap = TLSPeer.new(pem) { |socket, _| socket.write(reply) }
      [{ node: 2 }, { cluster: 'f' * 32 }, { voters: 5 }, :redirect, :hint].each do |bad|
        peer = TLSPeer.new(pem) do |socket, request|
          if bad == :redirect
            socket.write(reply('', status: 302, headers: { 'Location' => "https://127.0.0.1:#{trap.port}/" }))
          elsif bad == :hint
            socket.write(reply(JSON.generate({ node: 1, leader: 2, term: 1, role: 'follower', voters: 3, address: trap.seed })))
          else
            metadata(socket, request, **bad)
          end
        end
        begin
          error = assert_raises(Yamora::Error) { cluster_client([peer], pem, timeout: 0.16).put('a', 'b', 'n: 1') }
          refute error.uncertain?
          assert peer.requests.all? { |r| r[1]['authorization'] == "Bearer #{READ_TOKEN}" }
          assert peer.requests.none? { |r| r.first.start_with?('PUT ') }
        ensure
          peer.close
        end
      end
      assert_empty trap.requests
    ensure
      trap&.close
    end
  end

  def test_fair_discovery_and_stalled_cached_leader_use_one_deadline
    scratch do |dir|
      pem = certificates(dir)
      mode = :healthy
      slow = TLSPeer.new(pem) { |_, _| sleep 2 }
      cached = TLSPeer.new(pem) do |socket, request|
        if mode == :healthy
          socket.write(reply(JSON.generate(stored), headers: { 'ETag' => %Q("#{ETAG}") })) unless metadata(socket, request)
        else
          sleep 2
        end
      end
      final = TLSPeer.new(pem) do |socket, request|
        next if metadata(socket, request, node: 3)
        socket.write(reply(JSON.generate(stored), headers: { 'ETag' => %Q("#{ETAG}") }))
      end
      begin
        client = cluster_client([slow.seed(2), cached.seed, final.seed(3)], pem, timeout: 0.8, attempt_timeout: 0.3)
        before = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        client.put('a', 'b', 'n: 1')
        mode = :stall
        client.put('a', 'b', 'n: 1')
        assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - before, :<, 1.6
        assert final.requests.any? { |r| r.first.start_with?('PUT ') }
        failing = cluster_client([slow], pem, timeout: 0.12)
        before = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        error = assert_raises(Yamora::DeadlineError) { failing.put('a', 'b', 'n: 1') }
        refute error.uncertain?
        assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - before, :<, 0.4
      ensure
        slow.close; cached.close; final.close
      end
    end
  end

  def test_cancellation_before_and_during_dispatch_closes_socket_and_keeps_id
    scratch do |dir|
      pem = certificates(dir)
      arrived, closed = Queue.new, Queue.new
      peer = TLSPeer.new(pem) do |socket, request|
        next if metadata(socket, request)
        arrived << request
        socket.read # EOF must arrive on cancellation without GC.
        closed << true
      end
      begin
        client = cluster_client([peer], pem)
        token = Yamora::Cancellation.new
        token.cancel!
        error = assert_raises(Yamora::CancelledError) { client.with_request(cancellation: token) { |c| c.put('a', 'b', 'n: 1') } }
        refute error.uncertain?
        assert_empty peer.requests
        token = Yamora::Cancellation.new
        outcome = Queue.new
        worker = Thread.new do
          client.with_request(cancellation: token) { |c| c.put('a', 'b', 'n: 1') }
        rescue Yamora::Error => failure
          outcome << failure
        end
        request = Timeout.timeout(2) { arrived.pop }
        token.cancel!
        assert worker.join(1), 'cancelled worker did not close within its lifetime'
        assert Timeout.timeout(1) { closed.pop }, 'cancellation left the peer connected'
        error = outcome.pop
        assert_kind_of Yamora::UncertainWriteError, error
        assert_equal request[1]['x-yamora-request-id'], error.request_id
        assert_equal 'Yamora::CancelledError', error.reason
        # A cancelled operation must not poison a later context on the same client.
        assert_raises(Yamora::DeadlineError) { client.with_request(timeout: 0.02) { sleep 0.03; client.get('a', 'b') } }
      ensure
        worker&.kill&.join
        peer.close
      end
    end
  end

  def test_transaction_snapshot_and_concurrent_same_id_routing
    scratch do |dir|
      pem = certificates(dir)
      operations = [{ 'collection' => 'a', 'document' => 'b', 'put' => "n: 1\n" }]
      count = 0
      peer = TLSPeer.new(pem) do |socket, request|
        if metadata(socket, request)
          operations.clear
        else
          count += 1
          socket.write(reply(JSON.generate({ status: 'committed', operations: 1, revision: REV })))
        end
      end
      begin
        client = cluster_client([peer], pem)
        result = client.transaction(operations)
        assert_equal 1, result['operations']
        threads = 8.times.map do
          Thread.new { client.transaction([{ 'collection' => 'a', 'document' => 'b', 'put' => "n: 1\n" }], request_id: '4' * 32) }
        end
        threads.each { |thread| assert_equal result, thread.value }
        assert_equal 9, count
        requests = peer.requests.select { |r| r.first.start_with?('POST ') }
        assert requests.last(8).all? { |r| r[1]['x-yamora-request-id'] == '4' * 32 }
        assert requests.all? { |r| JSON.parse(r[2])['operations'].size == 1 }
      ensure
        peer.close
      end
    end
  end
end

class ClusterNativeHeaderTest < Minitest::Test
  include ClusterFixtures

  def test_native_repeated_no_store_is_valid_but_conflicting_cache_directives_are_not
    scratch do |dir|
      pem = certificates(dir)
      ['no-store', 'public'].each do |duplicate|
        peer = TLSPeer.new(pem) do |socket, request|
          next if metadata(socket, request)
          socket.write(reply(JSON.generate(stored), headers: { 'ETag' => %Q("#{ETAG}"), 'Cache-Control' => "no-store\r\nCache-Control: #{duplicate}" }))
        end
        begin
          client = cluster_client([peer], pem, timeout: 0.3)
          if duplicate == 'no-store'
            assert_equal stored, client.put('a', 'b', 'n: 1')
          else
            assert_raises(Yamora::UncertainWriteError) { client.put('a', 'b', 'n: 1') }
          end
        ensure
          peer.close
        end
      end
    end
  end
end

class ClusterCachedBindingTest < Minitest::Test
  include ClusterFixtures

  def test_cached_seed_reconfiguration_cannot_cross_cluster_node_or_voter_binding
    scratch do |dir|
      pem = certificates(dir)
      results = []
      [{ node: 2 }, { cluster: 'f' * 32 }, { voters: 5 }].each do |changed|
        binding = {}
        writes = 0
        peer = TLSPeer.new(pem) do |socket, request|
          next if metadata(socket, request, **binding)
          writes += 1
          socket.write(reply(JSON.generate(stored), headers: { 'ETag' => %Q("#{ETAG}") }))
        end
        begin
          client = cluster_client([peer], pem, timeout: 0.16)
          client.put('a', 'b', 'n: 1')
          binding = changed
          begin
            client.put('a', 'b', 'n: 2')
          rescue Yamora::Error => error
            results << [writes, error.uncertain?]
          else
            results << [writes, :accepted_wrong_binding]
          end
        ensure
          peer.close
        end
      end
      assert_equal [[1, false], [1, false], [1, false]], results
    end
  end
end
