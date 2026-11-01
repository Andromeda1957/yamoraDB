# frozen_string_literal: true

module Yamora
  class BinaryConfig
    attr_reader :host, :port, :server_name, :timeout, :concurrency, :max_frame

    def initialize(host:, port:, server_name:, ca_pem:, certificate_pem: nil, private_key_pem: nil,
                   timeout: 10, concurrency: 4, max_frame: 65_536)
      @host = BinaryInput.ascii(host, 15, nonempty: true)
      BinaryInput.require!(/\A(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}\z/n.match?(@host))
      octets = @host.split('.').map(&:to_i)
      private_ip = octets[0] == 127 || octets[0] == 10 || (octets[0] == 172 && octets[1].between?(16, 31)) || (octets[0] == 192 && octets[1] == 168)
      BinaryInput.require!(private_ip && octets.all? { |n| n <= 255 })
      BinaryInput.require!(BinaryInput.exact?(port, Integer) && port.between?(1, 65_535))
      @server_name = BinaryInput.ascii(server_name, 253, nonempty: true)
      # Explicit SAN identity; never used to resolve or route a connection.
      labels = @server_name.split('.', -1)
      BinaryInput.require!(labels.all? { |label| /\A[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\z/n.match?(label) })
      BinaryInput.require!(BinaryInput.exact?(concurrency, Integer) && concurrency.between?(1, 4))
      BinaryInput.require!(BinaryInput.exact?(max_frame, Integer) && max_frame.between?(4096, 65_536))
      @port, @timeout, @concurrency, @max_frame = port, BinaryInput.duration(timeout), concurrency, max_frame
      @ca_pem = BinaryInput.string(ca_pem, 1024 * 1024, nonempty: true)
      BinaryInput.require!(certificate_pem.nil? == private_key_pem.nil?)
      @certificate_pem = certificate_pem && BinaryInput.string(certificate_pem, 1024 * 1024, nonempty: true)
      @private_key_pem = private_key_pem && BinaryInput.string(private_key_pem, 1024 * 1024, nonempty: true)
      context # Parse owned material now; never retain a borrowed context/store.
      freeze
    rescue BinaryError, OpenSSL::OpenSSLError, ArgumentError, TypeError
      raise BinaryError.new(:config, 'yamora: invalid owned binary TLS configuration'), cause: nil
    end

    def inspect = "#<Yamora::BinaryConfig #{@host}:#{@port} verified TLS1.3>"

    private

    def certificates(pem)
      blocks = pem.scan(/-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+\/=\r\n]+-----END CERTIFICATE-----/n)
      remainder = pem.gsub(/-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+\/=\r\n]+-----END CERTIFICATE-----/n, '')
      BinaryInput.require!(blocks.size.between?(1, 64) && /\A[\r\n\t ]*\z/n.match?(remainder))
      blocks.map { |block| OpenSSL::X509::Certificate.new(block) }
    end

    def context(budget = nil)
      budget&.check
      context = OpenSSL::SSL::SSLContext.new
      context.min_version = context.max_version = OpenSSL::SSL::TLS1_3_VERSION
      context.verify_mode = OpenSSL::SSL::VERIFY_PEER
      context.verify_hostname = true
      context.alpn_protocols = ['yamora-binary/1']
      store = OpenSSL::X509::Store.new
      certificates(@ca_pem).each do |certificate|
        budget&.check
        store.add_cert(certificate)
      end
      context.cert_store = store # Explicit anchors only; never system/opaque trust.
      if @certificate_pem
        chain = certificates(@certificate_pem)
        context.cert = chain.shift
        context.extra_chain_cert = chain
        context.key = OpenSSL::PKey.read(@private_key_pem, '') # No interactive passphrase prompt.
        BinaryInput.require!(context.cert.check_private_key(context.key))
      end
      context.setup
      budget&.check
      context
    end
  end
end
