# frozen_string_literal: true

require_relative 'helper'

module ClusterFixtures
  include DriverFixtures
  CLUSTER = '01020304000000000000000000000000'

  class TLSPeer
    attr_reader :port, :requests

    def initialize(pem, &handler)
      @tcp = TCPServer.new('127.0.0.1', 0)
      @port = @tcp.addr[1]
      raise 'owner port allocated' if @port == 8000
      context = OpenSSL::SSL::SSLContext.new
      context.min_version = context.max_version = OpenSSL::SSL::TLS1_3_VERSION
      context.cert = OpenSSL::X509::Certificate.new(pem['server.pem'])
      context.key = OpenSSL::PKey.read(pem['server.key'])
      @requests, @workers, @sockets, @errors = [], [], [], Queue.new
      @mutex = Mutex.new
      @thread = Thread.new do
        loop do
          tcp = @tcp.accept
          @mutex.synchronize do
            @sockets << tcp
            @workers << Thread.new(tcp) do |raw|
              ssl = OpenSSL::SSL::SSLSocket.new(raw, context)
              ssl.sync_close = true
              begin
                Timeout.timeout(5) do
                  ssl.accept
                  first = ssl.gets("\r\n")
                  next unless first
                  headers = {}
                  while (line = ssl.gets("\r\n")) && line != "\r\n"
                    key, value = line.strip.split(':', 2)
                    headers[key.downcase] = value.strip
                  end
                  size = headers.fetch('content-length', '0').to_i
                  body = size.zero? ? ''.b : ssl.read(size)
                  request = [first.strip, headers, body]
                  @mutex.synchronize { @requests << request }
                  handler.call(ssl, request)
                end
              rescue OpenSSL::SSL::SSLError, IOError, SystemCallError
                # Clients may reject trust or close on cancellation/deadline.
              rescue StandardError => error
                @errors << error
              ensure
                ssl.close rescue nil
              end
            end
          end
        end
      rescue IOError, SystemCallError
        nil
      end
      @thread.report_on_exception = false
    end

    def seed(node = 1) = { host: '127.0.0.1', port: port, node: node }

    def close
      @tcp.close
      @thread.join
      @mutex.synchronize { @sockets.each { |s| s.close rescue nil } }
      @workers.each { |worker| worker.kill unless worker.join(0.1) }
      @workers.each(&:join)
      raise @errors.pop unless @errors.empty?
    end
  end

  def metadata(socket, request, node: 1, cluster: CLUSTER, voters: 3, role: 'leader')
    path = request.first.split[1]
    if path == '/v1/cluster/status'
      socket.write(reply(JSON.generate({ node: node, leader: node, term: 1, role: role, voters: voters })))
    elsif path == '/v1/changes'
      token = "v1.#{cluster}.0000000000000000"
      socket.write(reply(JSON.generate({ revision: REV, checkpoint: token, oldest_after: token, next_after: token, has_more: false, transactions: [] })))
    else
      return false
    end
    true
  end

  def cluster_client(peers, pem, **extra)
    seeds = peers.map { |peer| peer.is_a?(Hash) ? peer : peer.seed }
    Yamora::ClusterClient.new(seeds: seeds, cluster_id: CLUSTER, voters: 3,
                             tls: Yamora::TLS.new(ca_pem: pem['ca.pem']),
                             read_token: READ_TOKEN, write_token: WRITE_TOKEN, timeout: 2, **extra)
  end

  def stored(collection = 'a', document = 'b')
    { 'status' => 'stored', 'collection' => collection, 'document' => document, 'etag' => ETAG, 'revision' => REV }
  end

  def with_mutation_workers(barrier, gateway)
    workers = []
    begin
      yield workers
    ensure
      primary = $!
      failures = []
      begin
        barrier.release_dispatches
        barrier.release_responses
        workers.each do |worker|
          begin
            worker.kill unless worker.join(1)
            worker.join
          rescue Exception => error
            # Thread#join rethrows even non-StandardError worker failures.
            # Collect them only after each owned thread has terminated.
            failures << error
          end
        end
      ensure
        begin
          gateway.close
        rescue Exception => error
          failures << error
        end
      end
      raise failures.first unless primary || failures.empty?
    end
  end
end

module ClusterFixtures
  # The test controller observes fully dispatched mutations, releases native
  # forwarding together, then holds all native replies before client delivery.
  class MutationBarrier
    def initialize(timeout: 3)
      @timeout, @mutex, @changed = timeout, Mutex.new, ConditionVariable.new
      @requests, @responses, @pending = [], [], 0
      @dispatch_released, @responses_released = false, false
    end

    def dispatch(request)
      @mutex.synchronize do
        @requests << request
        @pending += 1
        @changed.broadcast
        wait { @dispatch_released }
      end
    end

    def response(response)
      @mutex.synchronize do
        @responses << response
        @changed.broadcast
        wait { @responses_released }
      end
    end

    def finished
      @mutex.synchronize { @pending -= 1; @changed.broadcast }
    end

    def pending = @mutex.synchronize { @pending }

    def drained
      @mutex.synchronize { wait { @pending.zero? } }
    end

    def requests(count)
      @mutex.synchronize do
        wait { @requests.size >= count }
        @requests.dup
      end
    end

    def responses(count)
      @mutex.synchronize do
        wait { @responses.size >= count }
        @responses.dup
      end
    end

    def release_dispatches
      @mutex.synchronize { @dispatch_released = true; @changed.broadcast }
    end

    def release_responses
      @mutex.synchronize { @responses_released = true; @changed.broadcast }
    end

    private

    def wait
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @timeout
      until yield
        remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
        raise 'native mutation barrier timed out' unless remaining > 0
        @changed.wait(@mutex, remaining)
      end
    end
  end
end
