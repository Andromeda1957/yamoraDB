# frozen_string_literal: true

require_relative 'helper'

class APITest < Minitest::Test
  include DriverFixtures

  def test_default_endpoint_matches_the_daemon_and_explicit_ports_are_preserved
    observed = []
    original = TCPSocket.method(:open)
    local_method = TCPSocket.singleton_class.instance_methods(false).include?(:open)
    TCPSocket.define_singleton_method(:open) do |address, port, *_arguments, **_keywords|
      observed << [address, port]
      raise Errno::ECONNREFUSED
    end
    assert_raises(Yamora::TransportError) { Yamora::Client.new.health }
    assert_raises(Yamora::TransportError) { Yamora::Client.new(port: 18765).health }
    assert_equal [['127.0.0.1', 8765], ['127.0.0.1', 18765]], observed
  ensure
    if local_method
      TCPSocket.define_singleton_method(:open, original)
    else
      TCPSocket.singleton_class.remove_method(:open)
    end
  end

  def test_json_responses_reject_nested_positive_and_negative_float_overflow
    %w[1.0e400 -1.0e400].each do |literal|
      ["{\"outer\":{\"inner\":[#{literal}]}}", "{\"outer\":[{\"inner\":#{literal}}]}"].each do |body|
        with_peer(->(socket, _) { socket.write(reply(body)) }) do |client, _|
          error = assert_raises(Yamora::ProtocolError) { client.health }
          refute error.uncertain?
          assert_nil error.cause
        end
      end
    end
  end

  def test_nonfinite_numbers_in_mutation_receipts_leave_outcome_uncertain
    body = %Q({"status":"stored","collection":"p","document":"a","etag":"#{ETAG}","revision":"#{REV}","extra":[{"value":1.0e400}]})
    with_peer(->(socket, _) { socket.write(reply(body)) }) do |client, peer|
      error = assert_raises(Yamora::ProtocolError) { client.patch('p', 'a', { '$set' => { 'x' => 1 } }) }
      assert error.uncertain?
      assert_equal 1, peer.requests.size
    end
  end

  def test_finite_float_boundaries_and_large_integers_remain_supported
    body = '{"nested":[{"positive":1.7976931348623157e308,"negative":-1.7976931348623157e308,"integer":9223372036854775807}]}'
    with_peer(->(socket, _) { socket.write(reply(body)) }) do |client, _|
      row = client.health['nested'].first
      assert_equal Float::MAX, row['positive']
      assert_equal(-Float::MAX, row['negative'])
      assert_equal 9_223_372_036_854_775_807, row['integer']
    end
  end

  def test_string_subclasses_cannot_invoke_custom_json_serializers
    calls = []
    custom = Class.new(String) do
      define_method(:to_json) do |*_arguments|
        calls << true
        '"injected"'
      end
    end
    handler = lambda do |socket, _|
      socket.write(reply(JSON.generate('status' => 'stored', 'collection' => 'p', 'document' => 'a', 'etag' => ETAG, 'revision' => REV)))
    end
    with_peer(handler) do |client, peer|
      client.patch('p', 'a', { '$set' => { custom.new('field') => custom.new('safe') } })
      assert_equal({ '$set' => { 'field' => 'safe' } }, JSON.parse(peer.requests.first[2]))
      assert_empty calls
    end
  end

  def test_query_preserves_compound_sort_large_integer_and_read_credential
    handler = lambda do |socket, (line, headers, body)|
      assert_equal 'POST /v1/query/people HTTP/1.1', line
      assert_equal "Bearer #{READ_TOKEN}", headers['authorization']
      spec = JSON.parse(body)
      assert_equal %w[rating age], spec['sort'].keys
      assert_equal 9_223_372_036_854_775_807, spec['filter']['n']
      socket.write(reply(JSON.generate('documents' => [{ 'id' => 'a', 'value' => { 'n' => 9_223_372_036_854_775_807 } }],
                                      'next_after' => nil, 'matched' => 1, 'revision' => REV)))
    end
    with_peer(handler) do |client, _|
      result = client.query('people', { 'filter' => { 'n' => 9_223_372_036_854_775_807 }, 'sort' => { 'rating' => -1, 'age' => 1 } })
      assert_equal 9_223_372_036_854_775_807, result['documents'].first['value']['n']
    end
  end

  def test_query_rejects_incomplete_rows_counts_and_progress
    good = { 'documents' => [{ 'id' => 'a', 'value' => {} }], 'next_after' => nil, 'matched' => 1, 'revision' => REV }
    bad = [good.reject { |key, _| key == 'revision' }, good.merge('documents' => nil), good.merge('matched' => nil),
           good.merge('matched' => -1), good.merge('next_after' => 'b'), good.merge('documents' => [{ 'id' => 'a' }]),
           good.reject { |key, _| key == 'next_after' }, good.merge('documents' => [good['documents'].first] * 2)]
    bad.each do |result|
      with_peer(->(socket, _) { socket.write(reply(JSON.generate(result))) }) do |client, _|
        assert_raises(Yamora::ProtocolError) { client.query('p') }
      end
    end
  end

  def test_job_publication_revision_is_independent_of_head_and_cancel_uses_write_auth
    job = { 'id' => 'a' * 32, 'status' => 'succeeded', 'phase' => 'done', 'documents_scanned' => 12,
            'transactions_replayed' => 2, 'revision' => 'f' * 16, 'error' => '', 'cancel_requested' => false }
    with_peer(->(socket, _) { socket.write(reply(JSON.generate(job))) }) do |client, _|
      assert_equal 'f' * 16, client.index_build('a' * 32)['revision']
    end
    running = job.merge('status' => 'running', 'phase' => 'scanning', 'revision' => '', 'cancel_requested' => true)
    handler = lambda do |socket, (line, headers, _)|
      assert_equal "DELETE /v1/index-builds/#{'a' * 32} HTTP/1.1", line
      assert_equal "Bearer #{WRITE_TOKEN}", headers['authorization']
      socket.write(reply(JSON.generate(running), status: 202))
    end
    with_peer(handler) { |client, _| assert client.cancel_index_build('a' * 32)['cancel_requested'] }
    [job.merge('id' => 'b' * 32), job.merge('revision' => ''), running.merge('phase' => 'done'), job.reject { |key, _| key == 'cancel_requested' }].each do |bad|
      with_peer(->(socket, _) { socket.write(reply(JSON.generate(bad))) }) do |client, _|
        assert_raises(Yamora::ProtocolError) { client.index_build('a' * 32) }
      end
    end
  end

  def test_transactions_preserve_raw_yaml_inside_json_and_require_receipts
    source = "# authored\r\nname: 'Exact'\r\n"
    op = { 'collection' => 'p', 'document' => 'a', 'put' => source, 'create_only' => true }
    handler = lambda do |socket, (_, headers, body)|
      assert_equal "Bearer #{WRITE_TOKEN}", headers['authorization']
      assert_equal source, JSON.parse(body)['operations'].first['put']
      assert_equal REV, JSON.parse(body)['revision']
      socket.write(reply(JSON.generate('status' => 'committed', 'operations' => 1, 'revision' => REV)))
    end
    with_peer(handler) { |client, _| assert_equal 1, client.transaction([op], revision: REV)['operations'] }
    with_peer(->(socket, _) { socket.write(reply(JSON.generate('status' => 'committed', 'operations' => 2, 'revision' => REV))) }) do |client, _|
      error = assert_raises(Yamora::ProtocolError) { client.transaction([op]) }
      assert error.uncertain?
    end
  end

  def test_search_and_aggregate_fail_closed_on_malformed_results
    replies = [{ 'documents' => [{ 'id' => 'a', 'score' => 0, 'value' => {} }], 'next_after' => nil,
                 'revision' => REV, 'documents_examined' => 1, 'index_entries_examined' => 1 },
               { 'documents' => [{ 'id' => 'a', 'score' => 1, 'value' => {} }], 'next_after' => 'b',
                 'revision' => REV, 'documents_examined' => 1, 'index_entries_examined' => 1 }]
    replies.each do |result|
      with_peer(->(socket, _) { socket.write(reply(JSON.generate(result))) }) do |client, _|
        assert_raises(Yamora::ProtocolError) { client.search('p', index: 'names', text: 'name') }
      end
    end
    with_peer(->(socket, _) { socket.write(reply(JSON.generate('documents' => [1], 'documents_examined' => 1, 'revision' => REV))) }) do |client, _|
      assert_raises(Yamora::ProtocolError) { client.aggregate('p', [{ '$count' => 'n' }]) }
    end
  end

  def test_changes_validate_identity_complete_frames_and_continuity
    token = ->(n) { "v1.#{'b' * 32}.#{n.to_s(16).rjust(16, '0')}" }
    frame = { 'token' => token.call(1), 'previous_revision' => 'e' * 16, 'revision' => REV,
              'resnapshot_required' => false, 'operations' => [{ 'collection' => 'p', 'document' => 'a', 'put' => "# feed\nx: 1\n" }] }
    good = { 'transactions' => [frame], 'next_after' => token.call(1), 'oldest_after' => token.call(0),
             'checkpoint' => token.call(1), 'has_more' => false, 'revision' => REV }
    with_peer(->(socket, _) { socket.write(reply(JSON.generate(good))) }) do |client, _|
      assert_equal "# feed\nx: 1\n", client.changes(after: token.call(0))['transactions'].first['operations'].first['put']
    end
    bad = [good.merge('has_more' => true), good.merge('next_after' => token.call(0)), good.merge('transactions' => []),
           good.merge('transactions' => [frame.merge('resnapshot_required' => true)]),
           good.merge('checkpoint' => "v1.#{'c' * 32}.0000000000000001"),
           good.merge('transactions' => [frame.merge('operations' => [{ 'collection' => 'p', 'document' => 'a', 'delete' => false }])])]
    bad.each do |result|
      with_peer(->(socket, _) { socket.write(reply(JSON.generate(result))) }) do |client, _|
        assert_raises(Yamora::ProtocolError) { client.changes(after: token.call(0)) }
      end
    end
  end
end
