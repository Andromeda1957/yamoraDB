# frozen_string_literal: true

require 'json'
require_relative '../lib/yamora'

module OperationsAdapter
  REQUIRED = %w[host port server-name ca-file cert-file key-file method target content-type feed source-file request-id timeout-ms max-frame-bytes cancel-mode output-dir].freeze
  module_function

  def arguments
    raise ArgumentError unless ARGV.length.even?
    values = {}
    ARGV.each_slice(2) do |flag, value|
      key = flag.delete_prefix('--')
      raise ArgumentError unless flag.start_with?('--') && (REQUIRED + %w[token-file if-match if-none-match]).include?(key) && !values.key?(key)
      values[key] = value
    end
    raise ArgumentError unless (REQUIRED - values.keys).empty? && values['host'] == '127.0.0.1' && values['server-name'] == 'localhost' && values['max-frame-bytes'] == '4096'
    raise ArgumentError unless %w[GET POST PATCH].include?(values['method']) && %w[none pre external].include?(values['cancel-mode'])
    raise ArgumentError unless /\A(?!0{32}\z)[0-9a-f]{32}\z/.match?(values['request-id'])
    { 'port' => 65_535, 'timeout-ms' => 30_000 }.each do |key, limit|
      raise ArgumentError unless /\A[1-9][0-9]*\z/.match?(values[key]) && values[key].to_i <= limit
    end
    raise ArgumentError unless %w[true false].include?(values['feed'])
    raise ArgumentError if values['feed'] == 'true' && (values['method'] != 'GET' || !values['content-type'].empty?)
    raise ArgumentError if values['port'].to_i == 8000
    values
  end

  def read(path, limit = 16 * 1024 * 1024)
    raise ArgumentError unless path.start_with?('/') && File.file?(path)
    bytes = File.binread(path, limit + 1) || ''.b
    raise ArgumentError if bytes.bytesize > limit
    bytes
  end

  def kind(error)
    { status: 'status', timeout: 'deadline', cancelled: 'cancelled', protocol: 'protocol',
      transport: 'transport', tls: 'transport', session: 'transport', unsupported: 'transport' }.fetch(error.kind)
  end

  def observe
    a = arguments
    source = read(a.fetch('source-file'))
    raise ArgumentError if a['method'] == 'GET' && !source.empty?
    root = File.realpath(a.fetch('output-dir'))
    raise ArgumentError unless a['output-dir'].start_with?('/') && File.directory?(root)
    file = lambda do |name, bytes|
      File.open(File.join(root, name), File::WRONLY | File::CREAT | File::EXCL, 0o600) { |io| io.binmode; io.write(bytes) }
      name
    end
    config = Yamora::BinaryConfig.new(host: a['host'], port: a['port'].to_i, server_name: a['server-name'],
                                     ca_pem: read(a['ca-file'], 1024 * 1024), certificate_pem: read(a['cert-file'], 1024 * 1024),
                                     private_key_pem: read(a['key-file'], 1024 * 1024), timeout: a['timeout-ms'].to_i / 1000.0,
                                     concurrency: 1, max_frame: a['max-frame-bytes'].to_i)
    client = Yamora::BinaryClient.new(config)
    cancellation = Yamora::BinaryCancellation.new
    cancellation.cancel if a['cancel-mode'] == 'pre'
    options = { cancel: cancellation, request_id: a['request-id'] }
    options[:token] = read(a['token-file'], 512) if a.key?('token-file')
    options[:if_match] = a['if-match'] if a.key?('if-match')
    options[:if_none_match] = a['if-none-match'] if a.key?('if-none-match')
    api = %w[status body_file etag revision representation_length request_id receipt].to_h { |key| [key, nil] }
    observation = { 'schema' => 'yamora-operation-observation/3', 'outcome' => 'success', 'error_kind' => nil,
                    'elapsed_ns' => 0, 'api' => api, 'envelope' => nil }
    feed_file = nil
    response = lambda do |value|
      api.merge!('status' => value.status, 'body_file' => a['feed'] == 'true' ? api['body_file'] : file.call('body.bin', value.body), 'etag' => value.etag,
                 'revision' => value.revision, 'representation_length' => value.representation_length, 'request_id' => value.request_id)
    end
    stop = false
    control_error = false
    control = nil
    pending = +''.b
    if a['cancel-mode'] == 'external'
      entered = Queue.new
      control = Thread.new do
        entered << true
        begin
          until stop
            next unless IO.select([$stdin], nil, nil, 0.02)
            part = $stdin.read_nonblock(3, exception: false)
            next if part == :wait_readable
            if part.nil?
              raise ArgumentError unless pending.empty?
              break
            end
            pending << part
            raise ArgumentError if pending.bytesize > 2 || pending.getbyte(0) != 67 || (pending.bytesize == 2 && pending.getbyte(1) != 10)
            if pending == "C\n"
              cancellation.cancel
              pending.clear
              break
            end
          end
          raise ArgumentError unless pending.empty?
        rescue StandardError
          control_error = true
          cancellation.cancel
        end
      end
      entered.pop
    end
    value = failure = nil
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    begin
      value = if a['feed'] == 'true'
                client.feed(a['target'], **options) do |raw, metadata|
                  feed_file ||= File.open(File.join(root, 'body.bin'), File::WRONLY | File::CREAT | File::EXCL, 0o600)
                  feed_file.binmode; feed_file.write(raw); api['body_file'] = 'body.bin'
                  response.call(metadata)
                end
              else
                client.operation(a['method'], a['target'], a['content-type'], source, **options)
              end
    rescue Yamora::BinaryError => error
      failure = error
    ensure
      observation['elapsed_ns'] = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) - started
      stop = true
      raise RuntimeError if control && !control.join(1)
      client.close
      feed_file&.close
    end
    raise ArgumentError if control_error
    if failure
      observation['error_kind'] = kind(failure)
      observation['outcome'] = observation['error_kind']
      if failure.is_a?(Yamora::BinaryUncertainWriteError) && failure.uncertain?
        original = failure.envelope
        observation['outcome'] = 'uncertain'
        observation['envelope'] = { 'method' => original.method, 'target' => original.target, 'content_type' => original.content_type,
                                    'if_match' => original.if_match, 'if_none_match' => original.if_none_match,
                                    'request_id' => original.request_id, 'source_file' => file.call('envelope.bin', original.source) }
      elsif failure.is_a?(Yamora::BinaryStatusError)
        response.call(failure.response)
      end
    else
      response.call(value)
    end
    observation
  end
end

begin
  json = JSON.generate(OperationsAdapter.observe) + "\n"
  raise RangeError if json.bytesize > 16_384
  $stdout.write(json)
rescue StandardError
  warn 'Ruby operations adapter failed'
  exit 2
end
