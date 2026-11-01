# frozen_string_literal: true

require_relative 'binary_helper'
require 'rbconfig'

# Deliberately break precise runtime guards in disposable SDK copies. A mutant
# is killed only by the exact behavioral assertion with confirmed TLS dispatch;
# compiler/loader errors, sanitizer reports, signals and deadlines are NOT red.
class BinaryMutantsTest < Minitest::Test
  include BinaryFixtures
  MUTANTS = {
    'missing_receipt_id' => ['binary_reply.rb', 'protocol!(r[:request_id] == e.request_id)', 'protocol!(true)'],
    'get_source_hash' => ['binary_reply.rb', 'protocol!(BinaryWire.source_etag(body, budget) == values[:etag])', 'protocol!(true)'],
    'create_only_status' => ['binary_reply.rb', "allowed = e.if_none_match == '*' ? [201] : !e.if_match.nil? ? [200] : [200, 201]", 'allowed = [200, 201]'],
    'incomplete_body_at_end' => ['binary_reply.rb', 'protocol!(body.bytesize == values[:body_length])', 'protocol!(true)'],
    'missing_end' => ['binary_client.rb', "BinaryWire.protocol!(payload.bytesize <= values[:body_length] - body.bytesize)\n              body << payload", "BinaryWire.protocol!(payload.bytesize <= values[:body_length] - body.bytesize)\n              body << payload; return BinaryReply.validate(values, body, envelope, budget)"],
    'immutable_uncertainty_envelope' => ['binary_client.rb', 'if dispatched && mutation_envelope?(envelope)', 'if false && mutation_envelope?(envelope)'],
    'bounded_source_snapshot' => ['binary_types.rb',
      "owned = String.instance_method(:byteslice).bind_call(value, 0, limit + 1)\n      size = owned.bytesize\n      require!(size <= limit && (!nonempty || size.positive?))\n      owned.force_encoding(Encoding::BINARY).freeze",
      "size = String.instance_method(:bytesize).bind_call(value)\n      require!(size <= limit && (!nonempty || size.positive?))\n      String.new(value).force_encoding(Encoding::BINARY).freeze"],
    'head_304_condition' => ['binary_reply.rb', "protocol!(status != 304 || e.if_none_match == '*' || e.if_none_match == r[:etag])", 'protocol!(status != 304 || !e.if_none_match.nil?)'],
    'get_304_condition' => ['binary_reply.rb', "protocol!(status != 304 || e.if_none_match == '*' || e.if_none_match == r[:etag])", 'protocol!(status != 304 || !e.if_none_match.nil?)']
  }.freeze

  def run_regression(sdk, name, dir)
    stdout, stderr = File.join(dir, 'stdout'), File.join(dir, 'stderr')
    pid = Process.spawn(RbConfig.ruby, File.join(sdk, 'tests/test_binary_regressions.rb'), '--name', "test_#{name}", '--seed', '1',
                        out: stdout, err: stderr, pgroup: true)
    status = nil
    begin
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 15
      loop do
        found, status = Process.wait2(pid, Process::WNOHANG)
        break if found
        raise 'mutant timeout is infrastructure failure, never regression proof' if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
        sleep 0.01
      end
    ensure
      unless status
        Process.kill('TERM', -pid)
        stop_owned(pid)
      end
    end
    [status, File.read(stdout), File.read(stderr)]
  end

  def test_exact_behavioral_mutants_red_then_restored_green
    MUTANTS.each do |name, (file, before, after)|
      scratch do |dir|
        sdk = File.join(dir, 'ruby')
        FileUtils.cp_r(File.expand_path('..', __dir__), sdk)
        target = File.join(sdk, 'lib/yamora', file)
        original = File.read(target)
        assert_equal 1, original.scan(before).size, "precise mutant anchor #{name}"
        File.write(target, original.sub(before, after))
        begin
          status, output, errors = run_regression(sdk, name, dir)
          assert status.exited? && status.exitstatus == 1, "#{name}: mutant did not reach an ordinary assertion: #{output}; #{errors}"
          assert_equal '', errors, "#{name}: infrastructure diagnostics cannot prove red"
          marker = name == 'bounded_source_snapshot' ? "SNAPSHOT:#{name}" : "DISPATCH:#{name}"
          assert_equal 1, output.scan(marker).size, "#{name}: coordinated race or actual REQUEST/END dispatch required"
          assert_match(/1 runs, \d+ assertions, 1 failures, 0 errors, 0 skips/, output)
          assert_includes output, "GUARD:#{name}"
          if name == 'bounded_source_snapshot'
            assert_includes output, 'Expected 16777217 to be <= 16777216.', 'require the exact oversized snapshot assertion'
          elsif name == 'immutable_uncertainty_envelope'
            assert_includes output, 'Yamora::BinaryUncertainWriteError'
            assert_includes output, 'not Yamora::BinaryError'
          else
            expected = %w[get_source_hash head_304_condition get_304_condition].include?(name) ? 'Yamora::BinaryError expected but nothing was raised.' : 'Yamora::BinaryUncertainWriteError expected but nothing was raised.'
            assert_includes output, expected, "#{name}: require exact behavioral assertion, never unrelated failures"
          end
          refute_match(/Sanitizer|runtime error:|SyntaxError|LoadError|Timeout::Error|timed out/, output)
        ensure
          File.write(target, original)
        end
        status, output, errors = run_regression(sdk, name, dir)
        assert status.exited? && status.success?, "#{name}: restored behavior did not pass: #{output}; #{errors}"
        assert_equal '', errors
        assert_equal 1, output.scan(marker).size
        assert_match(/1 runs, \d+ assertions, 0 failures, 0 errors, 0 skips/, output)
      end
    end
  end
  def test_schema2_transaction_count_is_behavioral
    scratch do |dir|
      sdk = File.join(dir, 'ruby')
      FileUtils.cp_r(File.expand_path('..', __dir__), sdk)
      target = File.join(sdk, 'lib/yamora/binary_operations.rb')
      original = File.read(target)
      anchor = "value['operations'] == request['operations'].size"
      assert_equal 1, original.scan(anchor).size
      run = lambda do
        Open3.capture3(RbConfig.ruby, File.join(sdk, 'tests/test_binary_operations.rb'), '--name', 'test_malformed_mode_and_transaction_receipt_preserve_original_envelope')
      end
      output, errors, status = run.call
      assert status.success?, output + errors
      File.write(target, original.sub(anchor, 'true'))
      output, errors, status = run.call
      assert status.exited? && status.exitstatus == 1, output + errors
      assert_equal '', errors
      assert_match(/1 runs, \d+ assertions, 1 failures, 0 errors, 0 skips/, output)
      assert_includes output, 'Yamora::BinaryUncertainWriteError expected but nothing was raised.'
      File.write(target, original)
      output, errors, status = run.call
      assert status.success?, output + errors
    end
  end

end
