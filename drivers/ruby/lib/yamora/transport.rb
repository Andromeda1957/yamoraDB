# frozen_string_literal: true

module Yamora
  # Net::HTTP does not bound header lines before allocating them. Extend only
  # this connection's BufferedIO, never global Net classes. The same budget
  # covers informational responses. Bounded endpoints reject chunked encoding.
  module HeaderBudget
    def readuntil(terminator, _ignore_eof = false)
      @yamora_header_bytes ||= 0
      @yamora_header_lines ||= 0
      line = +''.b
      loop do
        raise LimitError, 'yamora: response headers exceed limit' if @yamora_header_bytes >= 16 * 1024
        line << read(1)
        @yamora_header_bytes += 1
        break if line.end_with?(terminator)
      end
      @yamora_header_lines += 1
      if @yamora_header_lines > 66 || !line.end_with?("\r\n") || line.start_with?(' ', "\t")
        raise ProtocolError, 'yamora: invalid response headers'
      end
      line
    end
  end

  class BoundedHTTP < Net::HTTP
    attr_accessor :cancellation

    def release_cancellation
      @cancellation&.unregister(@cancellation_ticket) if @cancellation_ticket
      @cancellation_ticket = nil
    end

    private

    def timeouted_connect(*args)
      socket = super
      # Publish the cleanup handle before registration: Timeout::Error can
      # interrupt register after insertion and before its return value arrives.
      # Net::HTTP can reconnect before request dispatch even with retries off.
      # Keep one ticket so replacing/rejecting a registration cannot orphan it.
      @cancellation_ticket ||= Object.new if @cancellation
      @cancellation&.register(@cancellation_ticket) do
        begin
          # After handshake, close through BufferedIO/SSLSocket so the peer
          # receives TLS close_notify. Before publication, close the raw socket.
          connection = @socket
          connection = socket if !connection || connection.closed?
          connection.close unless connection.closed?
        rescue IOError, SystemCallError, OpenSSL::OpenSSLError
          # The exchange may have closed concurrently. This IO object cannot
          # close a descriptor later reused by another connection.
          nil
        end
      end
      socket
    rescue StandardError
      socket&.close unless socket&.closed?
      raise
    end

    def connect
      super
      if use_ssl? && !matching_ip_san?(@socket.io.peer_cert)
        raise OpenSSL::SSL::SSLError, 'yamora: endpoint IP SAN required'
      end
      @socket.extend(HeaderBudget)
    rescue StandardError
      # The base connect's rescue has already finished. A post-handshake
      # rejection must close this verified socket before HTTP can start.
      @socket&.close
      @socket = nil
      raise
    end

    def matching_ip_san?(certificate)
      extensions = certificate&.extensions&.select { |item| item.oid == 'subjectAltName' }
      return false unless extensions&.size == 1
      encoded = OpenSSL::ASN1.decode(extensions.first.to_der)
      return false unless encoded.is_a?(OpenSSL::ASN1::Sequence)
      octets = encoded.value.last
      return false unless octets.is_a?(OpenSSL::ASN1::OctetString)
      names = OpenSSL::ASN1.decode(octets.value)
      return false unless names.is_a?(OpenSSL::ASN1::Sequence) && names.to_der == octets.value
      expected = @address.split('.').map(&:to_i).pack('C4')
      names.value.any? do |name|
        name.tag_class == :CONTEXT_SPECIFIC && name.tag == 7 &&
          name.value.is_a?(String) && name.value.bytesize == 4 && name.value == expected
      end
    rescue OpenSSL::OpenSSLError, ArgumentError, TypeError
      false
    end
  end
  private_constant :HeaderBudget, :BoundedHTTP

  class TLS
    # PEM contents, not filenames or a mutable SSLContext. No verify-disable
    # switches, hostname override, callbacks or TLS downgrade options exist.
    def initialize(ca_pem: nil, certificate_pem: nil, private_key_pem: nil)
      Validation.require!(!certificate_pem.nil? == !private_key_pem.nil?, 'mTLS requires certificate and key')
      @ca_pem = ca_pem && Validation.utf8!(ca_pem, 1024 * 1024, nonempty: true).freeze
      @certificate_pem = certificate_pem && Validation.utf8!(certificate_pem, 1024 * 1024, nonempty: true).freeze
      @private_key_pem = private_key_pem && Validation.utf8!(private_key_pem, 1024 * 1024, nonempty: true).freeze
      Validation.require!(OpenSSL::SSL.const_defined?(:TLS1_3_VERSION), 'TLS 1.3 unavailable')
      # Validate before any network activity, and never retain a mutable store.
      configure(Net::HTTP.new('127.0.0.1', 1, nil))
      freeze
    end

    def inspect = '#<Yamora::TLS verified TLS1.3>'

    def configure(http)
      http.use_ssl = true
      http.min_version = OpenSSL::SSL::TLS1_3_VERSION
      http.max_version = OpenSSL::SSL::TLS1_3_VERSION
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.verify_hostname = true
      if @ca_pem
        store = OpenSSL::X509::Store.new
        certs = @ca_pem.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
        Validation.require!(!certs.empty?, 'CA certificates required')
        certs.each { |pem| store.add_cert(OpenSSL::X509::Certificate.new(pem)) }
        http.cert_store = store
      end
      if @certificate_pem
        certs = @certificate_pem.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
        Validation.require!(!certs.empty?, 'client certificate required')
        http.cert = OpenSSL::X509::Certificate.new(certs.shift)
        http.extra_chain_cert = certs.map { |pem| OpenSSL::X509::Certificate.new(pem) }
        http.key = OpenSSL::PKey.read(@private_key_pem, '')
        Validation.require!(http.cert.check_private_key(http.key), 'client key mismatch')
      end
    rescue OpenSSL::OpenSSLError, ArgumentError
      raise ArgumentError, 'yamora: invalid TLS credentials', cause: nil
    end
  end

  class Transport
    attr_reader :host, :port

    def initialize(host:, port:, read_token:, write_token:, tls:, timeout:, max_response_bytes:)
      Validation.require!(host.is_a?(String) && /\A(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}\z/.match?(host), 'numeric IPv4 required')
      octets = host.split('.').map(&:to_i)
      private_ip = octets[0] == 127 || octets[0] == 10 || (octets[0] == 172 && octets[1].between?(16, 31)) || (octets[0] == 192 && octets[1] == 168)
      Validation.require!(octets.all? { |n| n <= 255 } && private_ip, 'loopback or RFC1918 required')
      Validation.integer!(port, 1, 65_535)
      Validation.require!(timeout.is_a?(Numeric) && timeout.real? && timeout.finite? && timeout > 0 && timeout <= 30, 'timeout must be in (0, 30] seconds')
      Validation.require!(timeout.to_f.finite? && timeout.to_f > 0, 'timeout is too small')
      Validation.integer!(max_response_bytes, 1, MAX_RESPONSE_BYTES)
      Validation.require!(tls.nil? || tls.instance_of?(TLS), 'Yamora::TLS required')
      @host, @port, @timeout, @tls = host.dup.freeze, port, timeout.to_f, tls
      @max_response_bytes = max_response_bytes
      @read_token, @write_token = [read_token, write_token].map do |token|
        next nil if token.nil?
        Validation.require!(token.is_a?(String) && token.bytesize.between?(32, 512) && token.bytes.all? { |b| b.between?(33, 126) }, 'invalid credential')
        token.dup.freeze
      end
      freeze
    end

    def inspect = "#<Yamora::Transport #{@host}:#{@port}>"

    def request(method, path, body: nil, content_type: nil, headers: {}, write: false, maximum: MAX_RESPONSE_BYTES, statuses: [200], timeout: @timeout, on_dispatch: nil, cancellation: nil)
      maximum = [maximum, @max_response_bytes].min
      timeout = [timeout, @timeout].min
      # Explicit nil is essential: Net::HTTP.new otherwise defaults to :ENV.
      http = BoundedHTTP.new(@host, @port, nil)
      http.cancellation = cancellation
      http.max_retries = 0
      http.open_timeout = http.read_timeout = http.write_timeout = timeout
      http.ignore_eof = false if http.respond_to?(:ignore_eof=)
      @tls&.configure(http)
      request = Net::HTTPGenericRequest.new(method, !body.nil?, method != 'HEAD', path)
      request['Connection'] = 'close'
      request['Accept'] = 'application/json, application/yaml'
      request['Accept-Encoding'] = 'identity'
      request['Content-Type'] = content_type if content_type
      token = write ? @write_token : @read_token
      request['Authorization'] = "Bearer #{token}" if token
      headers.each { |key, value| request[key] = value }
      request.body = body if body
      result = nil
      # Socket timeouts alone permit an endless slow-drip response. A deadline
      # covers connect, handshake, headers and the entire body on a fresh socket.
      # Use a StandardError so Net::HTTP#connect closes its local TLS socket
      # even when the handshake expires before assigning @socket.
      Timeout.timeout(timeout, Timeout::Error) do
        http.start do
          on_dispatch&.call
          http.request(request) do |response|
            status = response.code.to_i
            raise HTTPError, status unless statuses.include?(status)
            response.each_header do |key, _|
              values = response.get_fields(key)
              # Native cluster diagnostics repeat this idempotent cache directive.
              # Framing, identity and all other headers remain single-valued.
              repeated_no_store = key == 'cache-control' && values.all? { |value| value == 'no-store' }
              raise ProtocolError, 'yamora: duplicate response header' unless values.size == 1 || repeated_no_store
            end
            if response['transfer-encoding'] || response['content-encoding'] || response['upgrade']
              raise ProtocolError, 'yamora: unsupported response framing or encoding'
            end
            length = response['content-length']
            unless length && /\A[0-9]{1,10}\z/.match?(length)
              raise ProtocolError, 'yamora: missing or invalid content length'
            end
            length = length.to_i
            raise LimitError, 'yamora: response exceeds byte limit' if length > maximum
            payload = +''.b
            response.read_body do |chunk|
              raise LimitError, 'yamora: response exceeds byte limit' if payload.bytesize + chunk.bytesize > maximum
              payload << chunk
            end
            raise ProtocolError, 'yamora: truncated response' unless payload.bytesize == length
            result = [payload, response.to_hash.transform_values(&:first), status]
          end
        end
      end
      result
    rescue Error => error
      error.mark_uncertain! if write && !(error.is_a?(HTTPError) && error.status.between?(400, 499) && error.status != 408)
      raise error, cause: nil
    rescue IOError, SystemCallError, SocketError, Timeout::Error, OpenSSL::OpenSSLError, Net::HTTPBadResponse, Net::ProtocolError
      error = TransportError.new('yamora: request transport failed')
      error.mark_uncertain! if write
      raise error, cause: nil
    ensure
      http&.release_cancellation
    end
  end
  private_constant :Transport
end
