# frozen_string_literal: true

require 'stringio'
require 'rbconfig'
require_relative 'cluster_helper'
require_relative '../conformance/http_replica'

# TLS peers below are negative controls for the adapter and public SDK boundary.
# They do not qualify native receipt persistence, elections, restart or quorum.
class HttpReplicaAdapterTest < Minitest::Test
  include ClusterFixtures
  ADAPTER = File.expand_path('../conformance/http_replica.rb', __dir__)
  SOURCE = "# receipt\r\nn: 0 # keep\r\n"
  PATCH = " { \"$inc\" : { \"n\" : 1 } }\n"
  API_NULL = %w[status body_file etag revision receipt].to_h { |key| [key, nil] }.freeze

  def with_root
    scratch do |root|
      pem = certificates(root)
      Dir.mkdir(File.join(root, 'input'), 0o700)
      (1..64).each { |seq| Dir.mkdir(File.join(root, format('call-%06d', seq)), 0o700) }
      File.binwrite(File.join(root, 'input/value-a.bin'), SOURCE)
      File.binwrite(File.join(root, 'input/patch.bin'), PATCH)
      File.binwrite(File.join(root, 'read.token'), READ_TOKEN)
      File.binwrite(File.join(root, 'write.token'), WRITE_TOKEN)
      config = {
        'schema' => 'yamora-http-replica-config/2', 'cluster_id' => CLUSTER, 'voters' => 3,
        'seeds' => (1..3).map { |node| { 'host' => '127.0.0.1', 'port' => 49000 + node, 'node' => node } },
        'tls' => { 'ca_file' => 'ca.pem', 'cert_file' => 'client.pem', 'key_file' => 'client.key' },
        'tokens' => { 'read_file' => 'read.token', 'write_file' => 'write.token' },
        'timeout_ms' => 15_000, 'attempt_timeout_ms' => 3000
      }
      write_config(root, config)
      yield root, pem, config
    end
  end

  def write_config(root, config)
    File.binwrite(File.join(root, 'config.json'), JSON.generate(config))
  end

  def argv(root) = ['--config', "#{root}/config.json", '--root', root]

  def call_command(seq = 1, **changes)
    { 'schema' => HttpReplicaAdapterV2::COMMAND_SCHEMA, 'seq' => seq, 'action' => 'call', 'method' => 'PATCH',
      'collection' => 'manifests', 'document' => 'counter', 'source_file' => 'input/patch.bin',
      'request_id' => '1' * 32, 'if_match' => %Q("#{ETAG}"), 'if_none_match' => nil }.merge(changes.transform_keys(&:to_s))
  end

  def close_command(seq) = { 'schema' => HttpReplicaAdapterV2::COMMAND_SCHEMA, 'seq' => seq, 'action' => 'close' }
  def recover_command(seq, handle = 'h1') = { 'schema' => HttpReplicaAdapterV2::COMMAND_SCHEMA, 'seq' => seq, 'action' => 'recover', 'handle' => handle }

  def run_input(root, bytes)
    output, diagnostic = StringIO.new, StringIO.new
    status = HttpReplicaAdapterV2.main(argv(root), input: StringIO.new(bytes), output: output, diagnostic: diagnostic)
    [status, output.string, diagnostic.string]
  end

  def run_commands(root, *commands)
    run_input(root, commands.map { |command| JSON.generate(command) + "\n" }.join)
  end

  def with_peers(handler)
    with_root do |root, pem, config|
      peers = []
      3.times do |index|
        peers << TLSPeer.new(pem) do |socket, request|
          next if metadata(socket, request, node: index + 1)
          handler.call(socket, request)
        end
      end
      config['seeds'] = peers.each_with_index.map { |peer, i| peer.seed(i + 1).transform_keys(&:to_s) }
      write_config(root, config)
      yield root, peers
    ensure
      primary, failures = $!, []
      peers&.each do |peer|
        begin
          peer.close
        rescue Exception => error
          failures << error
        end
      end
      raise failures.first unless primary || failures.empty?
    end
  end

  def receipt(socket, status: 200)
    socket.write(reply(JSON.generate(stored('manifests', 'counter')), status: status, headers: { 'ETag' => %Q("#{ETAG}") }))
  end

  def test_close_is_exact_and_eof_without_close_is_incomplete
    with_root do |root|
      status, output, diagnostic = run_commands(root, close_command(1))
      assert_equal 0, status
      assert_empty diagnostic
      value = JSON.parse(output)
      assert_equal 'yamora-http-replica-observation/2', value['schema']
      assert_equal ['closed', nil, 0, API_NULL], value.values_at('outcome', 'error_kind', 'elapsed_ns', 'api')
      %w[sdk_request_id envelope recovery_mode recovery_handle].each { |key| assert_nil value[key] }
      status, output, diagnostic = run_input(root, '')
      assert_equal 2, status
      assert_empty output
      assert_equal "Ruby HTTP replica adapter failed\n", diagnostic
    end
  end

  def test_protocol_malformed_lines_are_bounded_and_never_dispatch
    with_peers(->(*) { flunk 'invalid command reached SDK dispatch' }) do |root, peers|
      valid = JSON.generate(close_command(1))
      invalid = [
        "{\n", valid, "\n", "[]\n", "null\n", valid.sub('"seq":1', '"seq":1,"seq":1') + "\n",
        valid.sub('"seq":1', '"seq":NaN') + "\n", valid.sub('"seq":1', '"seq":1e999') + "\n",
        JSON.generate(close_command(2)) + "\n", JSON.generate(close_command(1).merge('extra' => WRITE_TOKEN)) + "\n",
        "{\"schema\":#{'[' * 13}0#{']' * 13}}\n", "\xff\n".b,
        (' ' * 16_384) + "\n", valid + (' ' * (16_384 - valid.bytesize)) + "\n"
      ]
      invalid.each do |line|
        status, output, diagnostic = run_input(root, line)
        assert_equal 2, status
        assert_empty output
        assert_equal "Ruby HTTP replica adapter failed\n", diagnostic
        refute_includes diagnostic, WRITE_TOKEN
      end
      assert_empty peers.flat_map(&:requests)
      # The size bound includes LF: exactly 16384 bytes still accepts valid JSON.
      status, output, = run_input(root, valid + (' ' * (16_383 - valid.bytesize)) + "\n")
      assert_equal 0, status
      assert_equal 'closed', JSON.parse(output)['outcome']
    end
  end

  def test_jsonl_raw_carriage_returns_reject_before_dispatch
    with_root do |root|
      line = JSON.generate(close_command(1))
      [line + "\r\n", "\r" + line + "\n", line.sub('"seq":1', "\"seq\":\r1") + "\n"].each do |bytes|
        status, output, diagnostic = run_input(root, bytes)
        assert_equal 2, status
        assert_empty output
        assert_equal "Ruby HTTP replica adapter failed\n", diagnostic
      end
    end
  end

  def test_json_numbers_are_integer_tokens_only
    %w[1.0 1e0 1E0 -0.0 0.5 1e999].each do |number|
      assert_raises(ArgumentError) { HttpReplicaAdapterV2.json("{\"number\":#{number}}") }
    end
    assert_equal({ 'number' => 1 }, HttpReplicaAdapterV2.json('{"number":1}'))
    assert_equal({ 'text' => "\r" }, HttpReplicaAdapterV2.json('{"text":"\\r"}'))
  end

  def test_config_and_token_file_bounds_match_strict_validator
    with_root do |root|
      path = File.join(root, 'config.json')
      original = File.binread(path)
      File.binwrite(path, original + (' ' * (16_384 - original.bytesize)))
      assert_equal 0, run_commands(root, close_command(1)).first
      File.binwrite(path, File.binread(path) + ' ')
      assert_equal 2, run_commands(root, close_command(1)).first
      File.binwrite(path, original)
      %w[read.token write.token].each do |name|
        path = File.join(root, name)
        File.binwrite(path, 't' * 512)
        assert_equal 0, run_commands(root, close_command(1)).first
        File.binwrite(path, 't' * 513)
        status, output, diagnostic = run_commands(root, close_command(1))
        assert_equal 2, status
        assert_empty output
        assert_equal "Ruby HTTP replica adapter failed\n", diagnostic
        File.binwrite(path, 't' * 512)
      end
    end
  end

  def test_pem_and_key_file_bounds_match_strict_config_validator
    with_root do |root|
      %w[ca.pem client.pem client.key].each do |name|
        path = File.join(root, name)
        original = File.binread(path)
        File.binwrite(path, original + (' ' * (16_384 - original.bytesize)))
        assert_equal 0, run_commands(root, close_command(1)).first
        File.binwrite(path, File.binread(path) + ' ')
        status, output, diagnostic = run_commands(root, close_command(1))
        assert_equal 2, status
        assert_empty output
        assert_equal "Ruby HTTP replica adapter failed\n", diagnostic
        File.binwrite(path, original)
      end
    end
  end

  def test_call_shape_conditions_ids_and_patch_value_reject_before_dispatch
    with_peers(->(*) { flunk 'invalid operation dispatched' }) do |root, peers|
      invalid = [
        { method: 'HEAD' }, { collection: 'yamldb-system' }, { collection: '../escape' }, { document: 'X' },
        { request_id: '' }, { request_id: '0' * 32 }, { request_id: 1 }, { if_match: ETAG },
        { if_match: '' }, { if_none_match: '*' }, { if_none_match: false }, { if_match: false },
        { method: 'GET', source_file: nil }, { method: 'DELETE', source_file: 'input/patch.bin' },
        { source_file: '../patch.bin' }, { source_file: '/input/patch.bin' }, { source_file: 'input/a/../patch.bin' },
        { source_file: 'input/PATCH.bin' }, { source_file: 'input/patch.bin', extra: true }, { seq: 1.0 }
      ]
      invalid.each do |changes|
        status, output, = run_commands(root, call_command(**changes), close_command(2))
        assert_equal 2, status, changes.inspect
        assert_empty output
      end
      ['{"$inc":{"n":1.0}}', '{"$inc":{"n":2}}', '{"$inc":{"n":true}}', '{"$inc":{"n":1,"n":1}}',
       '{"$inc":{"n":1},"other":1}', '{"$set":{"n":1}}', "\xff".b, '', ' ' * 131_073].each do |bytes|
        File.binwrite(File.join(root, 'input/patch.bin'), bytes)
        status, output, = run_commands(root, call_command, close_command(2))
        assert_equal 2, status
        assert_empty output
      end
      assert_empty peers.flat_map(&:requests)
    end
  end

  def test_exact_config_and_argv_cannot_redirect_credentials_or_budgets
    with_root do |root, _pem, original|
      variants = [
        original.merge('unknown' => WRITE_TOKEN), original.merge('voters' => 3.0), original.merge('cluster_id' => '0' * 32),
        original.merge('timeout_ms' => 15_001), original.merge('attempt_timeout_ms' => 3001),
        original.merge('tls' => original['tls'].merge('ca_file' => '../ca.pem')),
        original.merge('tokens' => original['tokens'].merge('write_file' => '/write.token'))
      ]
      [{ 'host' => 'localhost' }, { 'host' => '192.168.1.1' }, { 'port' => 8000 }, { 'port' => 65_536 },
       { 'port' => 1.0 }, { 'node' => 2 }, { 'extra' => true }].each do |changes|
        copy = JSON.parse(JSON.generate(original))
        copy['seeds'][0].merge!(changes)
        variants << copy
      end
      copy = JSON.parse(JSON.generate(original))
      copy['seeds'][1]['port'] = copy['seeds'][0]['port']
      variants << copy
      variants.each do |config|
        write_config(root, config)
        status, output, diagnostic = run_commands(root, close_command(1))
        assert_equal 2, status
        assert_empty output
        refute_includes diagnostic, WRITE_TOKEN
      end
      write_config(root, original)
      [argv(root) + ['--root', root], ['--config', "#{root}/other.json", '--root', root],
       ['--config', "#{root}/config.json", '--root', root, '--timeout', '100000']].each do |args|
        diagnostic = StringIO.new
        assert_equal 2, HttpReplicaAdapterV2.main(args, input: StringIO.new, output: StringIO.new, diagnostic: diagnostic)
        assert_equal "Ruby HTTP replica adapter failed\n", diagnostic.string
      end
    end
  end

  def test_symlink_config_is_rejected_before_sdk_construction
    with_root do |root|
      File.rename(File.join(root, 'config.json'), File.join(root, 'actual-config.json'))
      File.symlink(File.join(root, 'actual-config.json'), File.join(root, 'config.json'))
      status, output, diagnostic = run_commands(root, close_command(1))
      assert_equal 2, status
      assert_empty output
      assert_equal "Ruby HTTP replica adapter failed\n", diagnostic
    end
  end

  def test_files_symlink_components_nonregular_and_output_collisions_reject_before_dispatch
    with_peers(->(*) { flunk 'unsafe path dispatched' }) do |root, peers|
      input_file = File.join(root, 'input/patch.bin')
      File.rename(input_file, "#{input_file}.original")
      File.symlink("#{input_file}.original", input_file)
      assert_raises(ArgumentError) { HttpReplicaAdapterV2::Session.new(argv(root)).command(call_command) }
      File.unlink(input_file)
      File.rename("#{input_file}.original", input_file)

      # Even an in-root symlink directory is outside the frozen path contract.
      File.rename(File.join(root, 'input'), File.join(root, 'actual-input'))
      File.symlink(File.join(root, 'actual-input'), File.join(root, 'input'))
      assert_raises(ArgumentError) { HttpReplicaAdapterV2::Session.new(argv(root)).command(call_command) }
      File.unlink(File.join(root, 'input'))
      File.rename(File.join(root, 'actual-input'), File.join(root, 'input'))

      File.binwrite(File.join(root, 'call-000001/body.bin'), 'preserve')
      assert_raises(ArgumentError) { HttpReplicaAdapterV2::Session.new(argv(root)).command(call_command) }
      assert_equal 'preserve', File.binread(File.join(root, 'call-000001/body.bin'))
      assert_empty peers.flat_map(&:requests)

      config_path = File.join(root, 'config.json')
      File.rename(config_path, "#{config_path}.original")
      File.symlink("#{config_path}.original", config_path)
      assert_raises(ArgumentError) { HttpReplicaAdapterV2::Session.new(argv(root)) }
      File.unlink(config_path)
      File.rename("#{config_path}.original", config_path)
      File.rename(input_file, "#{input_file}.original")
      File.mkfifo(input_file, 0o600)
      assert_raises(ArgumentError) { HttpReplicaAdapterV2::Session.new(argv(root)).command(call_command) }
    end
  end

  def test_exact_source_api_exposure_conditions_and_no_success_id_echo
    requests = Queue.new
    handler = lambda do |socket, request|
      requests << request
      case request.first.split.first
      when 'GET'
        socket.write(reply(SOURCE, headers: { 'Content-Type' => 'application/yaml', 'ETag' => %Q("#{ETAG}") }))
      when 'DELETE'
        socket.write(reply('', status: 204))
      else
        receipt(socket, status: 201)
      end
    end
    with_peers(handler) do |root, _peers|
      commands = [call_command(1, method: 'PUT', source_file: 'input/value-a.bin', if_match: nil, if_none_match: '*'),
                  call_command(2, method: 'PUT', source_file: 'input/value-a.bin', if_match: nil),
                  call_command(3, method: 'GET', source_file: nil, request_id: nil, if_match: nil),
                  call_command(4, method: 'DELETE', source_file: nil), close_command(5)]
      status, output, diagnostic = run_commands(root, *commands)
      assert_equal 0, status
      assert_empty diagnostic
      observations = output.lines.map { |line| JSON.parse(line) }
      assert_equal %w[success success success success closed], observations.map { |item| item['outcome'] }
      observations.first(4).each do |item|
        assert_operator item['elapsed_ns'], :>, 0
        assert_operator item['elapsed_ns'], :<, 15_000_000_000
        %w[sdk_request_id envelope recovery_mode recovery_handle].each { |key| assert_nil item[key] }
        assert_nil item['api']['status']
      end
      assert_equal stored('manifests', 'counter'), observations[0]['api']['receipt']
      assert_equal [ETAG, REV], observations[0]['api'].values_at('etag', 'revision')
      assert_nil observations[0]['api']['body_file']
      assert_equal 'call-000003/body.bin', observations[2]['api']['body_file']
      assert_equal SOURCE.b, File.binread(File.join(root, observations[2]['api']['body_file']))
      assert_equal API_NULL.merge('revision' => REV), observations[3]['api']
      sent = 4.times.map { requests.pop }
      assert_equal SOURCE.b, sent[0][2]
      assert_equal '*', sent[0][1]['if-none-match']
      assert_nil sent[0][1]['if-match']
      assert_nil sent[1][1]['if-none-match']
      assert_nil sent[1][1]['if-match']
      assert_equal %Q("#{ETAG}"), sent[3][1]['if-match']
    end
  end

  def test_retains_actual_generated_and_supplied_uncertainty_and_reissues_frozen_patch
    [nil, '1' * 32].each do |supplied|
      requests, malformed = Queue.new, true
      handler = lambda do |socket, request|
        requests << request
        if malformed
          socket.write(reply(JSON.generate(stored('manifests', 'counter').merge('status' => 'failed')),
                             headers: { 'ETag' => %Q("#{ETAG}") }))
        else
          receipt(socket)
        end
      end
      with_peers(handler) do |root, _peers|
        session = HttpReplicaAdapterV2::Session.new(argv(root))
        uncertain = session.command(call_command(request_id: supplied))
        first = requests.pop
        id = first[1]['x-yamora-request-id']
        assert_equal ['uncertain', 'protocol', 'caller-reissue', 'h1', id], uncertain.values_at('outcome', 'error_kind', 'recovery_mode', 'recovery_handle', 'sdk_request_id')
        assert_match(/\A(?!0{32}\z)[0-9a-f]{32}\z/, id)
        assert_equal supplied, id if supplied
        assert_nil uncertain['envelope']
        assert_equal API_NULL, uncertain['api']
        retained = session.instance_variable_get(:@handles).fetch('h1')
        assert_instance_of Yamora::UncertainWriteError, retained.error
        assert_equal id, retained.error.request_id
        assert retained.primitive.frozen?
        assert retained.primitive[:source]['$inc'].frozen?
        assert retained.primitive[:options].frozen?

        # Recovery must not reread the modified source or generate a new ID.
        File.binwrite(File.join(root, 'input/patch.bin'), '{"$inc":{"n":9}}')
        second = session.command(recover_command(2))
        assert_equal ['uncertain', id, 'h1'], second.values_at('outcome', 'sdk_request_id', 'recovery_handle')
        malformed = false
        2.times do |index|
          recovered = session.command(recover_command(index + 3))
          assert_equal ['success', 'caller-reissue', 'h1', nil, nil], recovered.values_at('outcome', 'recovery_mode', 'recovery_handle', 'sdk_request_id', 'envelope')
          assert_equal stored('manifests', 'counter'), recovered['api']['receipt']
        end
        3.times do
          replay = requests.pop
          assert_equal first[0], replay[0]
          assert_equal first[2], replay[2]
          assert_equal %w[x-yamora-request-id if-match if-none-match].map { |key| first[1][key] },
                       %w[x-yamora-request-id if-match if-none-match].map { |key| replay[1][key] }
        end
        assert_equal({ '$inc' => { 'n' => 1 } }, JSON.parse(first[2]))
        assert_equal 'closed', session.command(close_command(5))['outcome']
        assert_empty session.instance_variable_get(:@handles)
      ensure
        session&.dispose
      end
    end
  end

  def test_status_rejection_never_manufactures_uncertainty_or_echoes_input_id
    with_peers(->(socket, _request) { socket.write(reply(WRITE_TOKEN, status: 409)) }) do |root, _peers|
      status, output, diagnostic = run_commands(root, call_command, close_command(2))
      assert_equal 0, status
      assert_empty diagnostic
      rejected = JSON.parse(output.lines.first)
      assert_equal ['status', 'status', API_NULL.merge('status' => 409)], rejected.values_at('outcome', 'error_kind', 'api')
      %w[sdk_request_id envelope recovery_mode recovery_handle].each { |key| assert_nil rejected[key] }
      refute_includes output, WRITE_TOKEN
    end
  end

  def test_raw_put_and_delete_recover_original_bytes_and_conditions
    %w[PUT DELETE].each do |method|
      malformed, writes = true, Queue.new
      with_peers(lambda do |socket, request|
        writes << request
        if malformed
          socket.write(reply('{bad'))
        elsif method == 'DELETE'
          socket.write(reply('', status: 204))
        else
          receipt(socket, status: 201)
        end
      end) do |root, _peers|
        session = HttpReplicaAdapterV2::Session.new(argv(root))
        args = method == 'PUT' ? { source_file: 'input/value-a.bin', if_match: nil, if_none_match: '*' } : { source_file: nil }
        first = session.command(call_command(method: method, request_id: nil, **args))
        assert_equal 'uncertain', first['outcome']
        original = writes.pop
        File.binwrite(File.join(root, 'input/value-a.bin'), "\xff".b)
        malformed = false
        result = session.command(recover_command(2))
        assert_equal 'success', result['outcome']
        recovered = writes.pop
        assert_equal original[0], recovered[0]
        assert_equal original[2], recovered[2]
        identity_conditions = %w[x-yamora-request-id if-match if-none-match]
        assert_equal identity_conditions.map { |key| original[1][key] }, identity_conditions.map { |key| recovered[1][key] }
        assert_nil result['sdk_request_id']
        assert_nil result['envelope']
        assert_equal 'caller-reissue', result['recovery_mode']
        if method == 'PUT'
          assert_equal SOURCE.b, recovered[2]
          assert_equal '*', recovered[1]['if-none-match']
          assert_equal stored('manifests', 'counter'), result['api']['receipt']
        else
          assert_empty recovered[2]
          assert_equal %Q("#{ETAG}"), recovered[1]['if-match']
          assert_equal API_NULL.merge('revision' => REV), result['api']
        end
      ensure
        session&.dispose
      end
    end
  end

  def test_unknown_handles_command_count_and_handle_count_are_bounded
    with_root do |root|
      %w[h0 h1 h17 ../../h1].each do |handle|
        session = HttpReplicaAdapterV2::Session.new(argv(root))
        assert_raises(ArgumentError) { session.command(recover_command(1, handle)) }
        session.dispose
      end
    end
    with_peers(->(socket, _request) { socket.write(reply('{bad')) }) do |root, _peers|
      session = HttpReplicaAdapterV2::Session.new(argv(root))
      16.times do |index|
        value = session.command(call_command(index + 1, request_id: nil))
        assert_equal "h#{index + 1}", value['recovery_handle']
      end
      assert_raises(ArgumentError) { session.command(call_command(17, request_id: nil)) }
      assert_equal 16, session.instance_variable_get(:@handles).size
      (17..64).each do |seq|
        value = session.command(recover_command(seq))
        assert_equal ['uncertain', 'h1'], value.values_at('outcome', 'recovery_handle')
      end
      assert_raises(ArgumentError) { session.command(recover_command(65)) }
      assert_equal 16, session.instance_variable_get(:@handles).size
    ensure
      session&.dispose
    end
  end

  def test_get_body_at_file_bound_and_oversized_response_are_bounded
    source = 'n: ' + ('x' * (131_072 - 3))
    with_peers(lambda do |socket, _request|
      socket.write(reply(source, headers: { 'Content-Type' => 'application/yaml', 'ETag' => %Q("#{ETAG}") }))
    end) do |root, _peers|
      session = HttpReplicaAdapterV2::Session.new(argv(root))
      result = session.command(call_command(method: 'GET', source_file: nil, request_id: nil, if_match: nil))
      assert_equal 'success', result['outcome']
      assert_equal source.b, File.binread(File.join(root, result['api']['body_file']))
      source += 'x'
      rejected = session.command(call_command(2, method: 'GET', source_file: nil, request_id: nil, if_match: nil))
      assert_equal ['protocol', 'protocol', API_NULL], rejected.values_at('outcome', 'error_kind', 'api')
      refute File.exist?(File.join(root, 'call-000002/body.bin'))
    ensure
      session&.dispose
    end
  end

  def test_executable_clean_close_eof_and_interrupt_stop_owned_process_and_socket
    # An actual in-flight public call is interrupted. This is cleanup evidence,
    # never a timeout/signal counted as a receipt regression red.
    entered, disconnected = Queue.new, Queue.new
    with_peers(lambda do |socket, _request|
      entered << true
      begin
        socket.read
      ensure
        disconnected << true
      end
    end) do |root, _peers|
      [[JSON.generate(close_command(1)) + "\n", 0], ['', 2]].each do |input, expected|
        launch(root) do |writer, reader, diagnostic, pid|
          writer.write(input)
          writer.close
          status = Timeout.timeout(5) { Process.wait2(pid).last }
          assert_equal expected, status.exitstatus
          text = reader.read
          if expected.zero?
            assert_equal 'closed', JSON.parse(text)['outcome']
          else
            assert_empty text
          end
          assert_operator diagnostic.read.bytesize, :<=, 16_384
        end
      end
      launch(root) do |writer, reader, diagnostic, pid|
        writer.write(JSON.generate(call_command) + "\n")
        writer.flush
        Timeout.timeout(5) { entered.pop }
        Process.kill('TERM', pid)
        status = Timeout.timeout(5) { Process.wait2(pid).last }
        refute status.success?
        assert_empty reader.read
        assert_equal "Ruby HTTP replica adapter interrupted\n", diagnostic.read
        assert Timeout.timeout(5) { disconnected.pop }
      end
    end
  end

  def launch(root)
    input_reader, input_writer = IO.pipe
    output_reader, output_writer = IO.pipe
    diagnostic_reader, diagnostic_writer = IO.pipe
    pid = Process.spawn(RbConfig.ruby, ADAPTER, *argv(root), in: input_reader, out: output_writer, err: diagnostic_writer)
    [input_reader, output_writer, diagnostic_writer].each(&:close)
    yield input_writer, output_reader, diagnostic_reader, pid
  ensure
    stop_owned(pid) if pid
    [input_reader, input_writer, output_reader, output_writer, diagnostic_reader, diagnostic_writer].compact.each do |io|
      io.close unless io.closed?
    end
  end
end
