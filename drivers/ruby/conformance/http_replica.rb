# frozen_string_literal: true

require 'pathname'
require_relative '../lib/yamora'

# The HTTP replica receipt v2 session uses only the public ClusterClient API.
# In particular Ruby has no prepared HTTP envelope: recovery reissues the
# frozen primitive using the ID on the retained, actual SDK exception.
module HttpReplicaAdapterV2
  LINE_LIMIT = 16_384
  FILE_LIMIT = 131_072
  COMMAND_SCHEMA = 'yamora-http-replica-command/2'
  OBSERVATION_SCHEMA = 'yamora-http-replica-observation/2'
  CONFIG_KEYS = %w[schema cluster_id voters seeds tls tokens timeout_ms attempt_timeout_ms].freeze
  CALL_KEYS = %w[schema seq action method collection document source_file request_id if_match if_none_match].freeze
  API_KEYS = %w[status body_file etag revision receipt].freeze
  RECEIPT_KEYS = %w[status collection document etag revision].freeze
  ID = /\A(?!0{32}\z)[0-9a-f]{32}\z/
  NAME = /\A[a-z0-9-]{1,128}\z/
  REVISION = /\A[0-9a-f]{16}\z/
  CONDITION = /\A"[0-9a-f]{16}"\z/
  Recovery = Struct.new(:primitive, :error)

  module_function

  def require!(condition)
    raise ArgumentError, 'invalid adapter input or result' unless condition
  end

  def keys!(value, keys)
    require!(value.instance_of?(Hash) && value.keys.sort == keys.sort)
  end

  def matches?(value, pattern)
    value.instance_of?(String) && value.ascii_only? && pattern.match?(value)
  end

  def utf8!(bytes, maximum, nonempty: false)
    require!(bytes.instance_of?(String) && bytes.bytesize <= maximum && (!nonempty || !bytes.empty?))
    text = bytes.dup.force_encoding(Encoding::UTF_8)
    require!(text.valid_encoding?)
    text
  end

  def json(bytes, maximum = LINE_LIMIT)
    value = JSON.parse(utf8!(bytes, maximum), max_nesting: 12, create_additions: false,
                       allow_nan: false, allow_duplicate_key: false)
    integer_numbers!(value)
    value
  end

  def integer_numbers!(value)
    case value
    when Hash then value.each_value { |item| integer_numbers!(item) }
    when Array then value.each { |item| integer_numbers!(item) }
    when Float then require!(false)
    end
  end

  def freeze_value(value)
    case value
    when Hash then value.each { |key, item| key.freeze; freeze_value(item) }
    when Array then value.each { |item| freeze_value(item) }
    end
    value.freeze
  end

  class Files
    def initialize(root)
      HttpReplicaAdapterV2.require!(root.instance_of?(String) && root.start_with?('/') && root.bytesize <= 4096)
      HttpReplicaAdapterV2.require!(Pathname.new(root).cleanpath.to_s == root && root != '/')
      @root = root.freeze
      # Check all ancestors as well as the session root; realpath alone would
      # silently accept symlink components in the launch path.
      directory!(@root)
      HttpReplicaAdapterV2.require!(File.stat(@root).uid == Process.uid)
    end

    def path(relative, directory: false)
      parts = relative.split('/')
      HttpReplicaAdapterV2.require!(!parts.empty? && parts.none? { |part| ['', '.', '..'].include?(part) })
      full = File.join(@root, relative)
      directory!(directory ? full : File.dirname(full))
      full
    end

    def read(relative, maximum = FILE_LIMIT)
      full = path(relative)
      before = File.lstat(full)
      HttpReplicaAdapterV2.require!(before.file? && before.uid == Process.uid)
      File.open(full, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |io|
        stat = io.stat
        HttpReplicaAdapterV2.require!(stat.file? && stat.dev == before.dev && stat.ino == before.ino && stat.size <= maximum)
        bytes = io.binmode.read(maximum + 1)
        HttpReplicaAdapterV2.require!(bytes.bytesize <= maximum)
        bytes
      end
    end

    def output_directory(seq)
      relative = format('call-%06d', seq)
      full = path(relative, directory: true)
      HttpReplicaAdapterV2.require!(File.stat(full).uid == Process.uid)
      %w[body.bin envelope.bin].each do |name|
        HttpReplicaAdapterV2.require!(!File.exist?(File.join(full, name)) && !File.symlink?(File.join(full, name)))
      end
      relative
    end

    def body(directory, bytes)
      HttpReplicaAdapterV2.require!(bytes.instance_of?(String) && bytes.bytesize <= FILE_LIMIT)
      relative = "#{directory}/body.bin"
      File.open(path(relative), File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) do |io|
        io.binmode.write(bytes)
      end
      relative
    end

    private

    def directory!(full)
      current = '/'
      full.split('/').reject(&:empty?).each do |part|
        current = File.join(current, part)
        HttpReplicaAdapterV2.require!(File.lstat(current).directory?)
      end
    end
  end

  class Session
    include HttpReplicaAdapterV2

    def initialize(argv)
      require!(argv.size == 4)
      arguments = {}
      argv.each_slice(2) do |key, value|
        require!(%w[--config --root].include?(key) && !arguments.key?(key))
        arguments[key] = value
      end
      root = arguments.fetch('--root')
      require!(arguments.fetch('--config') == "#{root}/config.json")
      @files = Files.new(root)
      config = json(@files.read('config.json', LINE_LIMIT))
      validate_config(config)
      tls = Yamora::TLS.new(ca_pem: @files.read('ca.pem', LINE_LIMIT), certificate_pem: @files.read('client.pem', LINE_LIMIT),
                            private_key_pem: @files.read('client.key', LINE_LIMIT))
      @client = Yamora::ClusterClient.new(seeds: config['seeds'].map { |seed| seed.transform_keys(&:to_sym) },
                  cluster_id: config['cluster_id'], voters: 3, tls: tls,
                  read_token: @files.read('read.token', 512), write_token: @files.read('write.token', 512),
                  timeout: 15, attempt_timeout: 3, max_response_bytes: FILE_LIMIT)
      @handles, @next_seq, @closed = {}, 1, false
    end

    def run(input, output)
      until @closed
        line = input.gets("\n", LINE_LIMIT + 1)
        require!(line && line.bytesize <= LINE_LIMIT && line.end_with?("\n") && !line.include?("\r"))
        observation = command(json(line))
        encoded = JSON.generate(observation, max_nesting: 12, allow_nan: false) + "\n"
        require!(encoded.bytesize <= LINE_LIMIT)
        output.write(encoded)
        output.flush
      end
    ensure
      dispose
    end

    def dispose
      # ClusterClient has no close method or persistent connection. Each public
      # operation releases its own TLS socket, including during interruption.
      @handles&.clear
      @client = nil
      @closed = true
    end

    def command(value)
      require!(!@closed && value.instance_of?(Hash) && value['schema'] == COMMAND_SCHEMA)
      require!(value['seq'].instance_of?(Integer) && value['seq'] == @next_seq && @next_seq <= 64)
      action = value['action']
      case action
      when 'close'
        keys!(value, %w[schema seq action])
        observation = blank(value, 'closed')
        dispose
      when 'call'
        keys!(value, CALL_KEYS)
        primitive = prepare(value)
        directory = @files.output_directory(@next_seq)
        observation = execute(value, primitive, directory)
      when 'recover'
        keys!(value, %w[schema seq action handle])
        require!(matches?(value['handle'], /\Ah(?:[1-9]|1[0-6])\z/) && @handles.key?(value['handle']))
        recovery = @handles.fetch(value['handle'])
        directory = @files.output_directory(@next_seq)
        observation = execute(value, recovery.primitive, directory, recovery: recovery)
      else
        require!(false)
      end
      @next_seq += 1
      observation
    end

    private

    def validate_config(config)
      keys!(config, CONFIG_KEYS)
      require!(config['schema'] == 'yamora-http-replica-config/2' && matches?(config['cluster_id'], ID))
      require!(config['voters'].instance_of?(Integer) && config['voters'] == 3)
      %w[timeout_ms attempt_timeout_ms].zip([15_000, 3000]).each do |key, expected|
        require!(config[key].instance_of?(Integer) && config[key] == expected)
      end
      require!(config['seeds'].instance_of?(Array) && config['seeds'].size == 3)
      config['seeds'].each do |seed|
        keys!(seed, %w[host port node])
        require!(seed['host'] == '127.0.0.1' && seed['port'].instance_of?(Integer) && seed['port'].between?(1, 65_535) && seed['port'] != 8000)
        require!(seed['node'].instance_of?(Integer))
      end
      require!(config['seeds'].map { |seed| seed['node'] }.sort == [1, 2, 3])
      require!(config['seeds'].map { |seed| seed['port'] }.uniq.size == 3)
      keys!(config['tls'], %w[ca_file cert_file key_file])
      require!(config['tls'] == { 'ca_file' => 'ca.pem', 'cert_file' => 'client.pem', 'key_file' => 'client.key' })
      keys!(config['tokens'], %w[read_file write_file])
      require!(config['tokens'] == { 'read_file' => 'read.token', 'write_file' => 'write.token' })
    end

    def prepare(value)
      method = value['method']
      require!(%w[GET PUT PATCH DELETE].include?(method))
      require!(matches?(value['collection'], NAME) && matches?(value['document'], NAME))
      id, match, none = value.values_at('request_id', 'if_match', 'if_none_match')
      require!(id.nil? || matches?(id, ID))
      require!(match.nil? || matches?(match, CONDITION))
      require!(none.nil? || none == '*')
      require!(!(match && none) && (none.nil? || method == 'PUT'))
      require!(method == 'GET' ? [id, match, none].all?(&:nil?) : value['collection'] != 'yamldb-system')
      options = {}
      options[:request_id] = id if id
      options[:etag] = match[1, 16] if match
      options[:create_only] = true if none
      source = nil
      if %w[PUT PATCH].include?(method)
        require!(matches?(value['source_file'], %r{\Ainput/[a-z0-9-]{1,64}\.bin\z}))
        source = utf8!(@files.read(value['source_file']), FILE_LIMIT, nonempty: true)
        if method == 'PATCH'
          source = json(source, FILE_LIMIT)
          keys!(source, ['$inc'])
          keys!(source['$inc'], ['n'])
          require!(source['$inc']['n'].instance_of?(Integer) && source['$inc']['n'] == 1)
        end
      else
        require!(value['source_file'].nil?)
      end
      freeze_value({ method: method, collection: value['collection'], document: value['document'], source: source, options: options })
    end

    def blank(value, outcome)
      { 'schema' => OBSERVATION_SCHEMA, 'seq' => value['seq'], 'action' => value['action'], 'outcome' => outcome,
        'error_kind' => nil, 'elapsed_ns' => 0, 'api' => API_KEYS.to_h { |key| [key, nil] },
        'sdk_request_id' => nil, 'envelope' => nil, 'recovery_mode' => nil, 'recovery_handle' => nil }
    end

    def execute(value, primitive, directory, recovery: nil)
      observation = blank(value, 'success')
      if recovery
        observation['recovery_mode'] = 'caller-reissue'
        observation['recovery_handle'] = value['handle']
      end
      options = primitive.fetch(:options)
      options = options.merge(request_id: recovery.error.request_id) if recovery
      result = failure = nil
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
      begin
        result = invoke(primitive, options)
      rescue Yamora::Error => error
        failure = error
      ensure
        observation['elapsed_ns'] = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) - started
      end
      if failure
        observation['api']['status'] = failure.status
        require!(failure.status.nil? || failure.status.instance_of?(Integer) && failure.status.between?(100, 599))
        if failure.is_a?(Yamora::UncertainWriteError)
          require!(failure.uncertain? && matches?(failure.request_id, ID) && primitive[:method] != 'GET')
          observation['outcome'] = 'uncertain'
          # reason is the SDK's typed cause class name, never peer error text.
          observation['error_kind'] = error_kind(failure.reason)
          observation['sdk_request_id'] = failure.request_id
          unless recovery
            require!(@handles.size < 16)
            handle = "h#{@handles.size + 1}"
            @handles[handle] = Recovery.new(primitive, failure).freeze
            observation['recovery_mode'] = 'caller-reissue'
            observation['recovery_handle'] = handle
          end
        else
          kind = error_kind(failure.class.name)
          require!(!kind.nil?)
          observation['outcome'] = observation['error_kind'] = kind
        end
      else
        expose(observation['api'], primitive, result, directory)
      end
      observation
    end

    def invoke(primitive, options)
      collection, document = primitive.values_at(:collection, :document)
      case primitive[:method]
      when 'GET' then @client.get(collection, document)
      when 'PUT' then @client.put(collection, document, primitive[:source], **options)
      when 'PATCH' then @client.patch(collection, document, primitive[:source], **options)
      when 'DELETE' then @client.delete(collection, document, **options)
      end
    end

    def error_kind(class_name)
      { 'Yamora::HTTPError' => 'status', 'Yamora::DeadlineError' => 'deadline', 'Yamora::CancelledError' => 'cancelled',
        'Yamora::ProtocolError' => 'protocol', 'Yamora::RevisionError' => 'protocol', 'Yamora::LimitError' => 'protocol',
        'Yamora::TransportError' => 'transport' }[class_name]
    end

    def expose(api, primitive, result, directory)
      case primitive[:method]
      when 'GET'
        require!(result.instance_of?(Yamora::Document) && matches?(result.etag, REVISION) && matches?(result.revision, REVISION))
        api['body_file'] = @files.body(directory, result.source)
        api['etag'], api['revision'] = result.etag, result.revision
      when 'DELETE'
        require!(matches?(result, REVISION))
        api['revision'] = result
      else
        require!(result.instance_of?(Hash) && (RECEIPT_KEYS - result.keys).empty?)
        receipt = result.slice(*RECEIPT_KEYS)
        require!(receipt['status'] == 'stored' && receipt['collection'] == primitive[:collection] && receipt['document'] == primitive[:document])
        require!(matches?(receipt['etag'], REVISION) && matches?(receipt['revision'], REVISION))
        api['receipt'], api['etag'], api['revision'] = receipt, receipt['etag'], receipt['revision']
      end
    end
  end

  def main(argv, input: $stdin, output: $stdout, diagnostic: $stderr)
    session = Session.new(argv)
    session.run(input, output)
    0
  rescue Interrupt
    diagnostic.write("Ruby HTTP replica adapter interrupted\n")
    130
  rescue StandardError
    # Never render exception messages, inspect, causes, source or credentials.
    diagnostic.write("Ruby HTTP replica adapter failed\n")
    2
  ensure
    session&.dispose
  end
end

if $PROGRAM_NAME == __FILE__
  Signal.trap('TERM') { raise Interrupt }
  Signal.trap('INT') { raise Interrupt }
  exit HttpReplicaAdapterV2.main(ARGV)
end
