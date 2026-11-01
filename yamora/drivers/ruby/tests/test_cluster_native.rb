# frozen_string_literal: true

require_relative 'native_cluster_helper'

class ClusterNativeTest < Minitest::Test
  include NativeClusterFixtures

  def forward(socket, response)
    body, headers, status = response
    socket.write("HTTP/1.1 #{status} Test\r\n#{headers.map { |k, v| "#{k}: #{v}\r\n" }.join}\r\n#{body}")
  end

  def overlapping_patches(cluster)
    target = cluster.leader
    upstream = cluster.endpoint(target, timeout: 10)
    barrier = MutationBarrier.new
    gateway = TLSPeer.new(cluster.pem) do |socket, request|
      method, path = request.first.split
      write = method == 'PATCH'
      begin
        barrier.dispatch(request) if write
        response = upstream.request(method, path, body: request[2].empty? ? nil : request[2],
                     content_type: request[1]['content-type'], headers: request[1].slice('x-yamora-request-id'),
                     write: write, statuses: [200])
        barrier.response(response) if write
        forward(socket, response)
      ensure
        barrier.finished if write
      end
    end
    with_mutation_workers(barrier, gateway) do |workers|
      6.times do
        workers << Thread.new do
          cluster.client(seeds: [gateway.seed(target + 1)]).patch('a', 'b', { '$inc' => { 'n' => 1 } }, request_id: '2' * 32)
        end
      end
      requests = barrier.requests(6)
      assert_equal 6, barrier.pending, 'mutations did not overlap before native dispatch'
      assert_equal ['2' * 32], requests.map { |request| request[1]['x-yamora-request-id'] }.uniq
      assert_equal ['{"$inc":{"n":1}}'], requests.map { |request| request[2] }.uniq
      barrier.release_dispatches
      native_responses = barrier.responses(6)
      assert_equal 6, barrier.pending, 'multiple mutations must remain outstanding before response release'
      assert workers.all?(&:alive?), 'a client returned before the response barrier was released'
      assert native_responses.all? { |response| response == native_responses.first }
      barrier.release_responses
      results = Timeout.timeout(10) { workers.map(&:value) }
      barrier.drained
      assert_equal 0, barrier.pending
      results
    end
  end

  def test_real_three_node_mtls_discovery_failover_lost_reply_quorum_loss_restart_and_receipts
    with_native_cluster do |cluster|
      client = cluster.client
      source = "# authored café\r\nname: 'Alpha'\r\nn: 0 # retain\r\nwide: 9223372036854775807\r\n"
      receipt = client.put('a', 'b', source, create_only: true, request_id: '1' * 32)
      assert_equal receipt, client.put('a', 'b', source, create_only: true, request_id: '1' * 32)
      assert_equal source.b, client.get('a', 'b').source.b
      assert_equal 9_223_372_036_854_775_807, client.query('a')['documents'].first['value']['wide']
      assert_includes client.collections['collections'], 'a'
      assert_equal ['b'], client.each_document('a').to_a
      error = assert_raises(Yamora::HTTPError) { client.patch('a', 'b', { '$inc' => { 'n' => 1 } }, etag: '0' * 16) }
      assert_equal 412, error.status
      refute error.uncertain?
      assert_raises(Yamora::TransportError) do
        seed = cluster.seeds.first.reject { |key, _| key == :node }
        Yamora::Client.new(**seed, tls: Yamora::TLS.new(ca_pem: cluster.pem['ca.pem'])).health
      end
      initial = client.changes
      old_leader = cluster.leader
      upstream = cluster.endpoint(old_leader, timeout: 10)
      dropped = false
      saved = nil
      gateway = TLSPeer.new(cluster.pem) do |socket, request|
        if dropped
          socket.write(reply('', status: 503))
          next
        end
        method, path = request.first.split
        write = method == 'PATCH'
        headers = request[1].slice('x-yamora-request-id', 'if-match', 'if-none-match')
        response = upstream.request(method, path, body: request[2].empty? ? nil : request[2],
                     content_type: request[1]['content-type'], headers: headers, write: write, statuses: [200])
        if write
          saved = [request, response]
          dropped = true
          cluster.stop(old_leader, crash: true)
          # Commit and receipt are durable; close without returning either.
        else
          forward(socket, response)
        end
      end
      begin
        routed = cluster.client(seeds: [gateway.seed(old_leader + 1), *cluster.seeds])
        recovered = routed.patch('a', 'b', { '$inc' => { 'n' => 1 } })
        assert dropped
        id = saved[0][1]['x-yamora-request-id']
        assert_match(/\A[0-9a-f]{32}\z/, id)
        original_receipt = JSON.parse(saved[1][0])
        assert_equal original_receipt, recovered
        assert_equal recovered, client.patch('a', 'b', { '$inc' => { 'n' => 1 } }, request_id: id)
        exact = source.sub('n: 0', 'n: 1')
        assert_equal exact.b, client.get('a', 'b').source.b
        frames = client.changes(after: initial['next_after'])['transactions']
        assert_equal 1, frames.flat_map { |frame| frame['operations'] }.count { |operation| operation['document'] == 'b' }
        # Rejoin the crashed node, then test concurrent same-ID dispatch.
        cluster.start(old_leader)
        results = overlapping_patches(cluster)
        assert results.all? { |result| result == results.first }
        exact = source.sub('n: 0', 'n: 2')
        assert_equal exact.b, client.get('a', 'b').source.b
        transaction = [{ 'collection' => 'a', 'document' => 'c', 'put' => "# tx\r\nn: 9\r\n", 'create_only' => true }]
        tx = client.transaction(transaction, request_id: '3' * 32)
        assert_equal tx, client.transaction(transaction, request_id: '3' * 32)
        indexes = [{ 'collection' => 'a', 'name' => 'n', 'fields' => ['n'] }]
        catalog = client.set_indexes(indexes, request_id: '4' * 32)
        assert_equal catalog, client.set_indexes(indexes, request_id: '4' * 32)
        deleted = client.delete('a', 'c', request_id: '5' * 32)
        client.put('a', 'c', "n: 10\n")
        assert_equal deleted, client.delete('a', 'c', request_id: '5' * 32)
        assert_equal "n: 10\n", client.get('a', 'c').source
        assert_equal 2, client.count('a')
        assert_raises(Yamora::HTTPError) { client.start_index_build([]) }
        current = cluster.leader
        short_write = cluster.client(timeout: 20, attempt_timeout: 0.15)
        short_write.get('a', 'b') # Warm routing with the ordinary setup budget.
        3.times { |i| cluster.stop(i) unless i == current }
        before = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        short = cluster.client(timeout: 0.4, attempt_timeout: 0.15)
        assert_raises(Yamora::DeadlineError) { short.get('a', 'b') }
        assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - before, :<, 1.2
        before = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        error = assert_raises(Yamora::DeadlineError) do
          short_write.with_request(timeout: 0.4) do
            short_write.put('a', 'quorum', "n: 99\n", create_only: true, request_id: '6' * 32)
          end
        end
        assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - before, :<, 1.2
        assert_equal '6' * 32, error.request_id
        refute error.uncertain? # Quorum-bound discovery prevented dispatch.
        cluster.stop(current)
        3.times { |i| cluster.start(i) }
        cluster.leader
        restarted = cluster.client
        resumed = restarted.put('a', 'quorum', "n: 99\n", create_only: true, request_id: '6' * 32)
        assert_equal resumed, restarted.put('a', 'quorum', "n: 99\n", create_only: true, request_id: '6' * 32)
        assert_equal "n: 99\n", restarted.get('a', 'quorum').source
        assert_equal exact.b, restarted.get('a', 'b').source.b
        assert_equal receipt, restarted.put('a', 'b', source, create_only: true, request_id: '1' * 32)
        assert_equal original_receipt, restarted.patch('a', 'b', { '$inc' => { 'n' => 1 } }, request_id: id)
        assert_equal results.first, restarted.patch('a', 'b', { '$inc' => { 'n' => 1 } }, request_id: '2' * 32)
        assert_equal catalog, restarted.set_indexes(indexes, request_id: '4' * 32)
        assert_equal tx, restarted.transaction(transaction, request_id: '3' * 32)
        assert_equal deleted, restarted.delete('a', 'c', request_id: '5' * 32)
        assert_equal exact.b, restarted.get('a', 'b').source.b
      ensure
        gateway.close
      end
    end
  end
end

class ClusterNativeReceiptTest < Minitest::Test
  include NativeClusterFixtures

  def test_native_committed_raw_transaction_catalog_bad_receipts_recover_original_id_and_bytes
    with_native_cluster do |cluster|
      cluster.client.put('a', 'b', "# retain\r\nn: 0\r\n")
      target = cluster.leader
      upstream = cluster.endpoint(target, timeout: 10)
      corrupt = false
      writes = []
      gateway = TLSPeer.new(cluster.pem) do |socket, request|
        method, path = request.first.split
        write = %w[PUT PATCH DELETE].include?(method) || method == 'POST' && path == '/v1/transactions'
        headers = request[1].slice('x-yamora-request-id', 'if-match', 'if-none-match')
        response = upstream.request(method, path, body: request[2].empty? ? nil : request[2],
                     content_type: request[1]['content-type'], headers: headers, write: write, statuses: [200, 201, 204])
        if write
          writes << [request, response]
          if corrupt
            corrupt = false
            socket.write(reply(JSON.generate({ status: 'failed', operations: 0, revision: response[1]['x-yamldb-revision'] }),
                         headers: { 'X-YamlDB-Revision' => response[1]['x-yamldb-revision'] }))
            next
          end
        end
        body, response_headers, status = response
        socket.write("HTTP/1.1 #{status} Test\r\n#{response_headers.map { |k, v| "#{k}: #{v}\r\n" }.join}\r\n#{body}")
      end
      begin
        client = cluster.client(seeds: [gateway.seed(target + 1)])
        definitions = [{ 'collection' => 'a', 'name' => 'n', 'fields' => ['n'] }]
        revision = client.indexes['revision']
        operations = [{ 'collection' => 'a', 'document' => 'tx', 'put' => "# transaction\r\nn: 7\r\n", 'create_only' => true }]
        [->(id) { client.set_indexes(definitions, revision: revision, request_id: id) },
         ->(id) { client.put('a', 'raw', "# café\r\nn: 1\r\n", create_only: true, request_id: id) },
         ->(id) { client.transaction(operations, request_id: id) }].each do |run|
          writes.clear
          corrupt = true
          error = assert_raises(Yamora::UncertainWriteError) { run.call(nil) }
          assert_equal 1, writes.size
          first_request, original = writes.first
          assert_equal first_request[1]['x-yamora-request-id'], error.request_id
          recovered = run.call(error.request_id)
          assert_equal JSON.parse(original[0]), recovered
          assert_equal writes.first, writes.last
        end
        assert_equal "# café\r\nn: 1\r\n".b, client.get('a', 'raw').source.b
        assert_equal "# transaction\r\nn: 7\r\n".b, client.get('a', 'tx').source.b
      ensure
        gateway.close
      end
    end
  end
end
