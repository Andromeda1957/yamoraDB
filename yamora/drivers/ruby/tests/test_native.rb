# frozen_string_literal: true

require_relative 'helper'

class NativeTest < Minitest::Test
  include DriverFixtures

  def assert_http(status)
    error = assert_raises(Yamora::HTTPError) { yield }
    assert_equal status, error.status
    refute error.uncertain?
  end

  def test_native_queries_preserve_all_unicode_separators
    scratch do |dir|
      with_native(dir) do |client, _|
        [0x85, 0x2028, 0x2029].each do |codepoint|
          value = "before#{codepoint.chr(Encoding::UTF_8)}after"
          id = "s#{codepoint}"
          source = "value: \"before\\u#{format('%04x', codepoint)}after\"\n"
          client.put('separators', id, source)
          result = client.query('separators', { 'filter' => { 'value' => value } })
          assert_equal [id], result['documents'].map { |row| row['id'] }
          assert_equal value, result['documents'].first['value']['value']
        end
      end
    end
  end

  def test_native_patches_preserve_all_unicode_separators
    scratch do |dir|
      with_native(dir) do |client, _|
        client.put('separators', 'patched', "# retain authored comment\nvalue: initial\n")
        [0x85, 0x2028, 0x2029].each do |codepoint|
          value = "before#{codepoint.chr(Encoding::UTF_8)}after"
          client.patch('separators', 'patched', { '$set' => { 'value' => value } })
          assert_equal value, client.query('separators')['documents'].first['value']['value']
          assert_includes client.get('separators', 'patched').source, '# retain authored comment'
        end
      end
    end
  end

  def test_native_transactions_preserve_all_unicode_separators_and_exact_source
    scratch do |dir|
      with_native(dir) do |client, _|
        client.put('separators', 'patched', 'value: initial')
        [0x85, 0x2028, 0x2029].each do |codepoint|
          separator = codepoint.chr(Encoding::UTF_8)
          value = "before#{separator}after"
          id = "s#{codepoint}"
          source = "# authored café\r\nvalue: \"before\\u#{format('%04x', codepoint)}after\"\r\n"
          receipt = client.transaction([
            { 'collection' => 'separators', 'document' => id, 'put' => source, 'create_only' => true },
            { 'collection' => 'separators', 'document' => 'patched', 'patch' => { '$set' => { 'value' => value } } }
          ])
          assert_equal 2, receipt['operations']
          assert_equal source.b, client.get('separators', id).source.b
          result = client.query('separators', { 'filter' => { 'value' => value } })
          assert_equal ['patched', id], result['documents'].map { |row| row['id'] }
        end
      end
    end
  end

  def test_native_nested_numbers_outside_ruby_float_range_are_rejected
    scratch do |dir|
      with_native(dir) do |client, _|
        %w[1.0e400 -1.0e400].each do |literal|
          source = "outer:\n  - nested:\n      value: #{literal}\n"
          client.put('numbers', 'overflow', source)
          assert_equal source, client.get('numbers', 'overflow').source
          error = assert_raises(Yamora::ProtocolError) { client.query('numbers') }
          refute error.uncertain?
        end
      end
    end
  end

  def test_native_source_conditions_queries_transactions_and_feed
    scratch do |dir|
      with_native(dir) do |client, port|
        assert_equal 2, client.health['api_version']
        assert_equal 'native-disk-v2', client.ready['storage']
        assert_kind_of Hash, client.stats
        assert_includes client.metrics, 'yam'
        assert_http(401) { Yamora::Client.new(port: port).collections }
        reader = Yamora::Client.new(port: port, read_token: READ_TOKEN)
        assert_http(401) { reader.put('people', 'unauthorized', 'name: blocked') }
        initial = client.changes
        source = "# Author's café\r\nname: 'Ada'  # keep quote and spaces\r\nactive: true\r\ncountry: US\r\nn: 9223372036854775807\r\nprofile:\r\n  city: Austin\r\nnotes: |\r\n  first\r\n  second\r\n"
        stored = client.put('people', 'ada', source, create_only: true)
        fetched = client.get('people', 'ada', revision: stored['revision'])
        assert_equal source.b, fetched.source.b
        assert_equal stored['etag'], fetched.etag
        assert_equal stored['revision'], fetched.revision
        assert_http(412) { client.put('people', 'ada', source, create_only: true) }
        assert_http(412) { client.patch('people', 'ada', { '$set' => { 'name' => 'No' } }, etag: '0' * 16) }
        assert_http(412) { client.delete('people', 'ada', etag: '0' * 16) }
        assert_equal source.b, client.get('people', 'ada').source.b
        changed = client.patch('people', 'ada', { '$set' => { 'profile.city' => 'Chicago', 'separator' => "A\u0085B" } }, etag: fetched.etag)
        patched = client.get('people', 'ada')
        assert_includes patched.source, "# Author's café"
        assert_includes patched.source, "name: 'Ada'  # keep quote and spaces"
        assert_includes patched.source, 'Chicago'
        refute_equal fetched.etag, changed['etag']
        client.put('people', 'bea', "name: Bea\nactive: true\ncountry: GB\nn: 42\n")
        client.put('people', 'cal', "name: Cal\nactive: false\ncountry: US\nn: 7\n")
        list = client.collections
        assert_includes list['collections'], 'people'
        assert_equal %w[ada bea cal], client.each_document('people', limit: 1).to_a
        page = client.query('people', { 'filter' => { 'active' => true }, 'sort' => { 'n' => 'desc', 'name' => 'asc' }, 'limit' => 1, 'explain' => true })
        assert_equal 'ada', page['documents'].first['id']
        assert_equal 9_223_372_036_854_775_807, page['documents'].first['value']['n']
        assert_equal "A\u0085B", page['documents'].first['value']['separator']
        assert_equal 2, page['matched']
        assert_kind_of Hash, page['explain']
        second = client.query('people', { 'filter' => { 'active' => true }, 'sort' => { 'n' => 'desc', 'name' => 'asc' }, 'limit' => 1, 'after' => page['next_after'], 'revision' => page['revision'] })
        assert_equal ['bea'], second['documents'].map { |row| row['id'] }
        assert_equal 2, client.count('people', { 'active' => true })
        assert_nil client.query('people', { 'include_count' => false })['matched']
        current = client.get('people', 'bea')
        transaction = client.transaction([
          { 'collection' => 'people', 'document' => 'bea', 'patch' => { '$inc' => { 'n' => 1 } }, 'etag' => current.etag },
          { 'collection' => 'people', 'document' => 'dee', 'put' => "# transaction source\nname: Dee\n", 'create_only' => true }
        ], revision: current.revision)
        assert_equal 2, transaction['operations']
        assert_equal "# transaction source\nname: Dee\n", client.get('people', 'dee').source
        assert_http(412) { client.query('people', { 'revision' => page['revision'] }) }
        assert_http(412) do
          client.transaction([
            { 'collection' => 'people', 'document' => 'never', 'put' => 'name: Never' },
            { 'collection' => 'people', 'document' => 'ada', 'delete' => true, 'etag' => '0' * 16 }
          ])
        end
        assert_http(404) { client.get('people', 'never') }
        feed = client.changes(after: initial['next_after'])
        operations = feed['transactions'].flat_map { |frame| frame['operations'] }
        assert operations.any? { |op| op['put'] == source }
        assert feed['transactions'].any? { |frame| frame['revision'] == transaction['revision'] && frame['operations'].size == 2 }
        assert_equal [], client.changes(after: feed['next_after'])['transactions']
        latest = client.get('people', 'dee')
        assert_match Yamora::REVISION, client.delete('people', 'dee', etag: latest.etag)
        assert_http(404) { client.get('people', 'dee') }
      end
    end
  end

  def test_native_indexes_aggregation_search_and_online_job
    scratch do |dir|
      with_native(dir) do |client, _|
        client.put('people', 'a', "name: Alice\ncountry: US\nrating: 2400\n")
        client.put('people', 'b', "name: Bob\ncountry: GB\nrating: 2600\n")
        client.put('people', 'c', "name: Alice\ncountry: US\nrating: 2800\n")
        catalog = client.indexes
        definitions = [{ 'collection' => 'people', 'name' => 'country-rating', 'fields' => %w[country rating], 'unique' => false },
                       { 'collection' => 'people', 'name' => 'names', 'fields' => ['name'], 'type' => 'text' }]
        client.set_indexes(definitions, revision: catalog['revision'])
        assert_equal %w[country-rating names], client.indexes['indexes'].map { |index| index['name'] }
        assert_http(412) { client.set_indexes([], revision: catalog['revision']) }
        result = client.search('people', index: 'names', text: 'Alice', limit: 1)
        assert_equal 'a', result['documents'].first['id']
        assert_equal ['c'], client.search('people', index: 'names', text: 'Alice', after: result['next_after'], revision: result['revision'])['documents'].map { |row| row['id'] }
        summary = client.aggregate('people', [
          { '$group' => { '_id' => '$country', 'n' => { '$sum' => 1 }, 'total' => { '$sum' => '$rating' } } },
          { '$sort' => { 'total' => -1, '_id' => 1 } }
        ])
        assert_equal({ '_id' => 'US', 'n' => 2, 'total' => 5200 }, summary['documents'].first)
        job = client.start_index_build(definitions, revision: client.ready['revision'])
        assert_match(/\A[0-9a-f]{32}\z/, job['id'])
        Timeout.timeout(10) do
          loop do
            job = client.index_build(job['id'])
            break unless job['status'] == 'running'
            sleep 0.02
          end
        end
        assert_equal 'succeeded', job['status']
        publication_revision = job['revision']
        client.put('people', 'd', 'name: Dana')
        assert_equal publication_revision, client.index_build(job['id'])['revision']
      end
    end
  end

  def test_native_large_document_and_replica_status
    scratch do |dir|
      with_native(dir, flags: ['--replica']) do |client, _|
        status = client.replication_status
        assert_equal 'uninitialized', status['status']
        assert_nil status['after']
        assert_http(405) { client.put('people', 'a', 'name: Ada') }
      end
    end
    scratch do |dir|
      with_native(dir) do |client, _|
        source = "# large source\ntext: |\n  #{'a' * (300 * 1024)}\n"
        client.put('large', 'a', source)
        assert_equal source, client.get('large', 'a').source
      end
    end
  end

  def test_native_verified_tls13_and_mutual_tls
    scratch do |dir|
      pem = certificates(dir)
      tls = Yamora::TLS.new(ca_pem: pem['ca.pem'], certificate_pem: pem['client.pem'], private_key_pem: pem['client.key'])
      flags = ['--tls-cert-file', File.join(dir, 'server.pem'), '--tls-key-file', File.join(dir, 'server.key'), '--tls-client-ca-file', File.join(dir, 'ca.pem')]
      with_native(dir, tls: tls, flags: flags) do |client, port|
        original = "# TLS source\r\nname: secure\r\n"
        client.put('secure', 'a', original)
        assert_equal original, client.get('secure', 'a').source
        untrusted = Yamora::TLS.new(certificate_pem: pem['client.pem'], private_key_pem: pem['client.key'])
        assert_raises(Yamora::TransportError) { Yamora::Client.new(port: port, tls: untrusted).health }
        missing_client = Yamora::TLS.new(ca_pem: pem['ca.pem'])
        assert_raises(Yamora::TransportError) { Yamora::Client.new(port: port, tls: missing_client).health }
        scratch do |other|
          rogue = certificates(other)
          wrong_client = Yamora::TLS.new(ca_pem: pem['ca.pem'], certificate_pem: rogue['client.pem'], private_key_pem: rogue['client.key'])
          assert_raises(Yamora::TransportError) { Yamora::Client.new(port: port, tls: wrong_client).health }
        end
        assert_http(401) { Yamora::Client.new(port: port, tls: tls).collections }
      end
    end
  end

  def test_native_server_hostname_is_verified
    [{ san: 'IP:127.0.0.2' }].each do |options|
      scratch do |dir|
        pem = certificates(dir, **options)
        tls = Yamora::TLS.new(ca_pem: pem['ca.pem'])
        with_native(dir, tls: tls, flags: ['--tls-cert-file', File.join(dir, 'server.pem'), '--tls-key-file', File.join(dir, 'server.key')]) do |client, _|
          error = assert_raises(Yamora::TransportError) { client.health }
          assert_nil error.cause
          refute error.uncertain?
        end
      end
    end
  end
end
