# frozen_string_literal: true

require 'yamora'

begin
  certificate = ENV['YAMORA_CLIENT_CERT_FILE']
  key = ENV['YAMORA_CLIENT_KEY_FILE']
  raise ArgumentError, 'supply both client identity files' if !!certificate != !!key

  tls = Yamora::TLS.new(
    ca_pem: File.binread(ENV.fetch('YAMORA_CA_FILE')),
    certificate_pem: certificate && File.binread(certificate),
    private_key_pem: key && File.binread(key)
  )
  client = Yamora::Client.new(
    host: ENV.fetch('YAMORA_HOST', '127.0.0.1'),
    port: Integer(ENV.fetch('YAMORA_PORT'), 10), tls: tls,
    read_token: ENV.fetch('YAMORA_READ_TOKEN'),
    write_token: ENV.fetch('YAMORA_WRITE_TOKEN')
  )
  collection = ENV.fetch('YAMORA_COLLECTION', 'package-demo')
  document = ENV.fetch('YAMORA_DOCUMENT', 'ruby')
  original = "# authored café\r\nname: Ada\r\nvisits: 1\r\n"
  updated = "# edited café, still CRLF\r\nname: Ada Lovelace\r\nvisits: 2\r\n"

  client.put(collection, document, original, create_only: true)
  read = client.get(collection, document)
  raise 'source changed' unless read.source.b == original.b
  client.put(collection, document, updated, etag: read.etag)
  read = client.get(collection, document)
  raise 'updated source changed' unless read.source.b == updated.b
  client.delete(collection, document, etag: read.etag)
  begin
    client.get(collection, document)
    raise 'deleted document still exists'
  rescue Yamora::HTTPError => error
    raise unless error.status == 404
  end
  puts 'CRUD_OK'
rescue StandardError
  warn 'CRUD failed; reconcile any uncertain write before retrying.'
  exit 1
end
