# frozen_string_literal: true

require_relative 'cluster_helper'

class ClusterCleanupTest < Minitest::Test
  include ClusterFixtures

  def test_failed_worker_cleanup_stops_every_worker_and_tls_gateway
    assert_equal [true, 0, 0, false], cleanup_outcome(timeout: false)
  end

  def test_timeout_cleanup_preserves_timeout_and_stops_every_worker_and_tls_gateway
    assert_equal [true, 0, 0, false], cleanup_outcome(timeout: true)
  end

  def cleanup_outcome(timeout:)
    scratch do |dir|
      pem = certificates(dir)
      entered, failed, blocked = Queue.new, Queue.new, Queue.new
      gateway = TLSPeer.new(pem) { |_socket, _request| entered << true; blocked.pop }
      workers = []
      failure = RuntimeError.new('owned worker failed')
      primary = Timeout::Error.new('owned controller timed out')
      raised = nil
      begin
        with_mutation_workers(MutationBarrier.new, gateway) do |owned|
          workers = owned
          workers << Thread.new do
            Thread.current.report_on_exception = false
            raise failure
          ensure
            failed << true
          end
          Timeout.timeout(1) { failed.pop }
          workers << Thread.new do
            Thread.current.report_on_exception = false
            Yamora::Client.new(port: gateway.port, tls: Yamora::TLS.new(ca_pem: pem['ca.pem']), timeout: 5).health
          end
          Timeout.timeout(1) { entered.pop }
          workers << Thread.new { blocked.pop }
          raise primary if timeout
        end
      rescue StandardError => error
        raised = error
      end
      gateway_threads = [gateway.instance_variable_get(:@thread), *gateway.instance_variable_get(:@workers)]
      [raised.equal?(timeout ? primary : failure), workers.count(&:alive?), gateway_threads.count(&:alive?), accepting?(gateway.port)]
    ensure
      # The regression must also leave no fixtures behind when run against the
      # broken cleanup. These references belong exclusively to this test.
      workers&.each do |worker|
        worker.kill if worker.alive?
        worker.join
      rescue StandardError
        nil
      end
      gateway&.close unless gateway&.instance_variable_get(:@tcp)&.closed?
    end
  end

  def accepting?(port)
    socket = Socket.tcp('127.0.0.1', port, connect_timeout: 0.2)
    true
  rescue Errno::ECONNREFUSED
    false
  ensure
    socket&.close
  end
end
