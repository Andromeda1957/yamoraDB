# frozen_string_literal: true
require_relative 'binary_native_helper'

class BinaryOperationsNativeTest < Minitest::Test
  include BinaryNativeFixtures
  def test_native_raw_operations_and_complete_page_feed
    native_test do |daemon|
      client = daemon.client(max_frame: 4096)
      source = "# exact spelling\r\nn: 9223372036854775807\r\ntext: hello\r\n"
      client.put('operations', 'one', source, token: WRITE_TOKEN)
      query = client.operation('POST', '/v1/query/operations', 'application/json', '{"limit":1}', token: READ_TOKEN)
      assert_includes query.body, '9223372036854775807'
      patch = client.operation('PATCH', '/v1/collections/operations/documents/one', 'application/json', '{"$set":{"text":"changed"}}', token: WRITE_TOKEN)
      assert_equal patch.revision, JSON.parse(patch.body)['revision']
      raw = "# transaction raw\r\nn: 4\r\n"
      spec = JSON.generate('operations' => [{ 'collection' => 'operations', 'document' => 'two', 'put' => raw }])
      tx = client.operation('POST', '/v1/transactions', 'application/json', spec, token: WRITE_TOKEN)
      assert_equal 1, JSON.parse(tx.body)['operations']
      assert_equal raw, client.get('operations', 'two', token: READ_TOKEN).body
      after = daemon.http.changes['next_after']
      pages = []
      result = client.feed("/v1/changes/stream?after=#{after}&duration_ms=150&heartbeat_ms=100", token: READ_TOKEN) { |page| pages << page }
      assert_operator pages.size, :>=, 1
      assert_equal after, result.resume_after
      assert pages.all? { |page| page.frozen? && page.end_with?("\n") && JSON.parse(page)['next_after'] == after }
      cancelled = Yamora::BinaryCancellation.new
      prefix = []
      error = assert_raises(Yamora::BinaryError) do
        client.feed("/v1/changes/stream?after=#{after}", token: READ_TOKEN, cancel: cancelled) { |page| prefix << page; cancelled.cancel }
      end
      assert_equal :cancelled, error.kind
      assert_equal 1, prefix.size
      client.close
    end
  end
end
