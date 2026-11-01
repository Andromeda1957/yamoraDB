# frozen_string_literal: true

require_relative 'helper'
require 'digest'

module BinaryFixtures
  include DriverFixtures
  ID = '102030405060708090a0b0c0d0e0f001'
  SOURCE = "# café λ\r\nv: 01 # retain\r\ntext: '雪'\r\n".freeze

  def binary_config(port, pem, **extra)
    Yamora::BinaryConfig.new(host: '127.0.0.1', port: port, server_name: '127.0.0.1', ca_pem: pem.fetch('ca.pem'),
                            certificate_pem: pem['client.pem'], private_key_pem: pem['client.key'], timeout: 30, **extra)
  end

  def native_etag(source)
    number = 1469598103934665603
    source.each_byte { |byte| number = (number ^ byte) * 1099511628211 & 0xffffffffffffffff }
    format('"%016x"', number)
  end

  # Independent literal wire peer. No production encoder/parser is used here.
  def bin_frame(kind, stream, payload = ''.b)
    ['YMBF', 1, kind, 0, stream, payload.bytesize].pack('a4CCnNN') + payload
  end

  def bin_fields(fields)
    [1, fields.size].pack('nn') + fields.map { |id, bytes| [id, bytes.bytesize].pack('nn') + bytes }.join
  end

  def parse_fields(payload)
    schema, count = payload.unpack('nn')
    raise 'bad request schema' unless schema == 1
    fields, offset = {}, 4
    count.times do
      id, size = payload.byteslice(offset, 4).unpack('nn')
      offset += 4
      raise 'bad request TLV' if fields.key?(id) || size > payload.bytesize - offset
      fields[id] = payload.byteslice(offset, size)
      offset += size
    end
    raise 'request trailing bytes' unless offset == payload.bytesize
    fields
  end

  def bin_read(socket)
    header = socket.read(16)
    raise EOFError unless header && header.bytesize == 16
    magic, version, kind, flags, stream, size = header.unpack('a4CCnNN')
    raise 'bad client framing' unless magic == 'YMBF' && version == 1 && flags == 0 && size <= 65_536
    payload = size.zero? ? ''.b : socket.read(size)
    raise EOFError unless payload && payload.bytesize == size
    [kind, stream, payload]
  end

  def read_request(socket)
    kind, stream, payload = bin_read(socket)
    raise 'client HELLO absent' unless [kind, stream] == [1, 0] && payload.bytesize == 12
    socket.write(bin_frame(1, 0, [1, 1, 4096, 1].pack('nnNN')))
    kind, stream, payload = bin_read(socket)
    raise 'client REQUEST absent' unless [kind, stream] == [2, 1]
    fields, source = parse_fields(payload), +''.b
    loop do
      kind, stream, payload = bin_read(socket)
      raise 'client stream mismatch' unless stream == 1
      break if kind == 5 && payload.empty?
      raise 'client DATA invalid' unless kind == 4 && !payload.empty? && source.bytesize + payload.bytesize <= 16 * 1024 * 1024
      source << payload
    end
    raise 'client body mismatch' unless fields.fetch(4).unpack1('Q>') == source.bytesize
    { fields: fields, source: source, method: fields.fetch(1).unpack1('C') }
  end

  def response_parts(request, source: SOURCE, status: nil, changes: {}, body: nil)
    method = request.fetch(:method)
    collection, document = request.fetch(:fields).fetch(2).split('/')[3..].values_at(0, 2)
    status ||= method == 3 ? (request[:fields][7] == '*' ? 201 : 200) : method == 4 ? 204 : 200
    etag = native_etag(method == 3 ? request[:source] : source)
    receipt = { 'status' => 'stored', 'collection' => collection, 'document' => document, 'etag' => etag[1, 16], 'revision' => REV }
    body ||= status >= 400 ? '{"error":"rejected"}' : method == 3 ? JSON.generate(receipt) : method == 1 ? source.b : ''.b
    media = status >= 400 || method >= 3 ? 'application/json' : 'application/yaml'
    fields = { 1 => [status].pack('n'), 2 => media, 3 => [body.bytesize].pack('Q>'),
               4 => [method == 2 && status < 400 ? source.bytesize : body.bytesize].pack('Q>'), 5 => REV }
    fields[6] = etag if status < 400 && method != 4
    fields[7], fields[8] = collection, document
    fields[12] = request[:fields][8] if request[:fields].key?(8)
    changes.each { |id, value| value.nil? ? fields.delete(id) : fields[id] = value }
    [fields.sort.to_h, body.b]
  end

  def send_response(socket, request, fragment: false, **options)
    fields, body = response_parts(request, **options)
    frames = bin_frame(3, 1, bin_fields(fields))
    offset = 0
    while offset < body.bytesize
      frames << bin_frame(4, 1, body.byteslice(offset, 4096))
      offset += 4096
    end
    frames << bin_frame(5, 1)
    if fragment
      frames.each_byte { |byte| socket.write([byte].pack('C')) }
    else
      socket.write(frames)
    end
  end

  class BinaryPeer
    include BinaryFixtures
    attr_reader :port, :requests, :accepted

    def initialize(pem, alpn: 'yamora-binary/1', version: OpenSSL::SSL::TLS1_3_VERSION, handshake_failure: false, raw: false, &handler)
      @listener = TCPServer.new('127.0.0.1', 0)
      @port = @listener.addr[1]
      raise 'owner port allocated' if @port == 8000
      context = OpenSSL::SSL::SSLContext.new
      context.min_version = context.max_version = version
      context.cert = OpenSSL::X509::Certificate.new(pem.fetch('server.pem'))
      context.key = OpenSSL::PKey.read(pem.fetch('server.key'), '')
      context.alpn_select_cb = ->(_protocols) { alpn } if alpn
      @mutex, @sockets, @threads, @errors, @requests, @accepted = Mutex.new, [], [], Queue.new, [], Queue.new
      @stopping = false
      @acceptor = Thread.new do
        loop do
          socket = @listener.accept
          @mutex.synchronize { @sockets << socket }
          thread = Thread.new(socket) do |owned|
            tls = nil
            begin
              tls = OpenSSL::SSL::SSLSocket.new(owned, context)
              tls.sync_close = true
              tls.accept
              @accepted << true
              if raw
                handler.call(tls, self)
              else
                request = read_request(tls)
                @mutex.synchronize { @requests << request }
                handler.call(tls, request, self)
              end
            rescue OpenSSL::SSL::SSLError, EOFError, Errno::ECONNRESET, Errno::EPIPE => error
              @errors << error unless handshake_failure || @stopping
            rescue IOError, Errno::EBADF => error
              @errors << error unless @stopping
            rescue StandardError => error
              @errors << error
            ensure
              tls&.close rescue nil
              owned.close unless owned.closed?
            end
          end
          thread.report_on_exception = false
          @mutex.synchronize { @threads << thread }
        end
      rescue IOError, Errno::EBADF
        # This fixture closes its listener during close.
      end
      @acceptor.report_on_exception = false
    end

    def close
      @stopping = true
      @listener.close unless @listener.closed?
      raise 'acceptor did not join' unless @acceptor.join(5)
      @mutex.synchronize { @sockets.each { |socket| socket.close unless socket.closed? } }
      failures = []
      @threads.each { |thread| failures << 'binary TLS handler did not join' unless thread.join(5) }
      raise failures.first unless failures.empty?
      raise @errors.pop unless @errors.empty?
    end
  end

  def await(queue, timeout: 5)
    Timeout.timeout(timeout) { queue.pop }
  end

  def join_owners(threads)
    failures = []
    threads.each { |thread| failures << 'binary call owner did not join' unless thread.join(5) }
    raise failures.first unless failures.empty?
  end

  def peer_test(handler, peer_options: {}, config_options: {})
    scratch do |dir|
      pem = certificates(dir)
      peer = BinaryPeer.new(pem, **peer_options, &handler)
      begin
        client = Yamora::BinaryClient.new(binary_config(peer.port, pem, **config_options))
        yield client, peer, pem
      ensure
        peer.close
      end
    end
  end

  def binary_failure(kind, uncertain: false)
    error = assert_raises(uncertain ? Yamora::BinaryUncertainWriteError : Yamora::BinaryError) { yield }
    assert_equal kind, error.kind
    assert_equal uncertain, error.uncertain?
    error
  end
end
