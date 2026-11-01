# frozen_string_literal: true

module Yamora
  Document = Struct.new(:source, :etag, :revision, keyword_init: true)

  class Client
    def initialize(host: '127.0.0.1', port: 8765, read_token: nil, write_token: nil,
                   tls: nil, timeout: 5, max_response_bytes: MAX_RESPONSE_BYTES)
      @transport = Transport.new(host: host, port: port, read_token: read_token,
                                 write_token: write_token, tls: tls, timeout: timeout,
                                 max_response_bytes: max_response_bytes)
      freeze
    end

    def inspect = "#<Yamora::Client #{@transport.host}:#{@transport.port}>"
    def health = json_call('GET', '/healthz')
    def ready = json_call('GET', '/readyz')
    # Advisory preflight before application-owned stages; native admission wins.
    def require_replication_source
      result = ready
      if result.key?('replication_policy_free')
        allowed = result['replication_policy_free']
        protocol!(allowed.equal?(true) || allowed.equal?(false), 'invalid replication source capability')
        raise SchemaPolicyReplicationError unless allowed
      end
      result
    end
    def stats = json_call('GET', '/v1/stats')

    def metrics
      body, headers = @transport.request('GET', '/metrics', maximum: MAX_DOCUMENT_BYTES)
      check_revision(headers['x-yamldb-revision'])
      check_media(headers, ['text/plain'])
      response_text(body)
    end

    # Catalog/list methods add the validated header revision to the result hash.
    def collections(revision: nil)
      Validation.optional_revision!(revision)
      result = json_call('GET', '/v1/collections', expected_revision: revision)
      protocol!(names?(result['collections'], 65_536), 'invalid collection catalog')
      result
    end

    def document_page(collection, limit: 1000, after: nil, revision: nil)
      Validation.identifier!(collection)
      Validation.integer!(limit, 1, 1000)
      Validation.optional_revision!(revision)
      if after
        Validation.identifier!(after)
        Validation.require!(!revision.nil?, 'continuation requires revision')
      end
      path = "/v1/collections/#{collection}/documents?limit=#{limit}"
      path += "&after=#{after}" if after
      result = json_call('GET', path, expected_revision: revision)
      docs = result['documents']
      protocol!(result['collection'] == collection && names?(docs, limit) && result.key?('next_after'), 'invalid document page')
      protocol!(docs.empty? || after.nil? || docs.first > after, 'non-progressing document page')
      protocol!(result['next_after'].nil? || (!docs.empty? && result['next_after'] == docs.last), 'invalid page cursor')
      result
    end

    # Revision is pinned across pages. Previously yielded effects cannot be
    # undone if a later request detects a concurrent database change.
    def each_document(collection, revision: nil, limit: 1000)
      return enum_for(__method__, collection, revision: revision, limit: limit) unless block_given?
      after = nil
      loop do
        page = document_page(collection, limit: limit, after: after, revision: revision)
        revision = page['revision']
        page['documents'].each { |id| yield id }
        after = page['next_after']
        break unless after
      end
      revision
    end

    def get(collection, document, revision: nil)
      Validation.optional_revision!(revision)
      body, headers = @transport.request('GET', document_path(collection, document), maximum: MAX_DOCUMENT_BYTES)
      check_revision(headers['x-yamldb-revision'], revision)
      check_media(headers, %w[application/yaml text/yaml])
      etag = headers['etag']
      protocol!(etag.is_a?(String) && /\A"[0-9a-f]{16}"\z/.match?(etag), 'invalid document ETag')
      Document.new(source: response_text(body), etag: etag[1, 16], revision: headers['x-yamldb-revision']).freeze
    end

    def put(collection, document, source, etag: nil, create_only: false)
      path = document_path(collection, document)
      source = Validation.source!(source)
      headers = Validation.preconditions(etag, create_only)
      mutate do
        result = json_call('PUT', path, raw_body: source, content_type: 'application/yaml',
                           headers: headers, write: true, statuses: [200, 201], require_body_revision: true)
        stored!(result, collection, document)
      end
    end

    def patch(collection, document, operations, etag: nil)
      path = document_path(collection, document)
      Validation.require!(operations.is_a?(Hash) && !operations.empty?, 'nonempty patch required')
      headers = Validation.preconditions(etag)
      mutate do
        result = json_call('PATCH', path, value: operations, headers: headers, write: true, request_maximum: MAX_REQUEST_BYTES, require_body_revision: true)
        stored!(result, collection, document)
      end
    end

    def delete(collection, document, etag: nil)
      path = document_path(collection, document)
      headers = Validation.preconditions(etag)
      mutate do
        _, response = @transport.request('DELETE', path, headers: headers, write: true, maximum: 0, statuses: [204])
        check_revision(response['x-yamldb-revision'])
      end
    end

    # String-keyed Hashes retain Ruby insertion order for compound sort priority.
    # Server validates predicate/operator semantics before executing queries.
    def query(collection, spec = {})
      Validation.identifier!(collection)
      spec = query_spec(spec)
      result = json_call('POST', "/v1/query/#{collection}", value: spec, expected_revision: spec['revision'], require_body_revision: true)
      rows = result['documents']
      protocol!(rows.is_a?(Array) && rows.size <= spec.fetch('limit', 100) && result.key?('matched') && result.key?('next_after'), 'invalid query page')
      ids = []
      rows.each do |row|
        protocol!(row.is_a?(Hash) && Validation.matches?(row['id'], IDENTIFIER) && row.key?('value'), 'invalid query row')
        ids << row['id']
      end
      protocol!(ids.uniq.size == ids.size, 'duplicate query row')
      matched = result['matched']
      protocol!((uint?(matched) && matched >= rows.size) || (matched.nil? && spec['include_count'] == false && !spec['count_only']), 'invalid query count')
      cursor = result['next_after']
      protocol!(cursor.nil? || (!rows.empty? && cursor == rows.last['id'] && cursor != spec['after']), 'invalid query cursor')
      protocol!(!spec['count_only'] || (rows.empty? && cursor.nil?), 'invalid count result')
      protocol!(!spec['explain'] || result['explain'].is_a?(Hash), 'missing query explanation')
      result
    end

    def count(collection, filter = {}, revision: nil)
      spec = { 'filter' => filter, 'count_only' => true }
      spec['revision'] = revision if revision
      query(collection, spec)['matched']
    end

    def aggregate(collection, pipeline, revision: nil)
      Validation.identifier!(collection)
      Validation.optional_revision!(revision)
      Validation.require!(pipeline.is_a?(Array) && pipeline.size.between?(1, 32) && pipeline.all? { |stage| stage.is_a?(Hash) && stage.size == 1 }, 'invalid pipeline')
      spec = { 'pipeline' => pipeline }
      spec['revision'] = revision if revision
      result = json_call('POST', "/v1/aggregate/#{collection}", value: spec, expected_revision: revision, require_body_revision: true)
      rows = result['documents']
      protocol!(rows.is_a?(Array) && rows.size <= 65_536 && rows.all? { |row| row.is_a?(Hash) } && uint?(result['documents_examined']), 'invalid aggregate result')
      result
    end

    def search(collection, index:, text:, mode: 'all', filter: {}, limit: 100, after: nil, revision: nil)
      Validation.identifier!(collection)
      Validation.identifier!(index)
      Validation.utf8!(text, 8192, nonempty: true)
      Validation.require!(%w[all any].include?(mode) && filter.is_a?(Hash), 'invalid search arguments')
      Validation.integer!(limit, 1, 1000)
      continuation!(after, revision)
      spec = { 'index' => index, 'text' => text, 'mode' => mode, 'filter' => filter, 'limit' => limit }
      spec['after'] = after if after
      spec['revision'] = revision if revision
      result = json_call('POST', "/v1/search/#{collection}", value: spec, expected_revision: revision, require_body_revision: true)
      rows = result['documents']
      protocol!(rows.is_a?(Array) && rows.size <= limit && result.key?('next_after'), 'invalid search result')
      previous = after || ''
      rows.each do |row|
        protocol!(row.is_a?(Hash) && Validation.matches?(row['id'], IDENTIFIER) && row['id'] > previous && row.key?('value') && row['score'].is_a?(Integer) && row['score'].between?(1, 32), 'invalid search row')
        previous = row['id']
      end
      protocol!(result['next_after'].nil? || (!rows.empty? && result['next_after'] == previous), 'invalid search cursor')
      examined, entries = result.values_at('documents_examined', 'index_entries_examined')
      protocol!(uint?(examined) && examined >= rows.size && uint?(entries) && entries >= examined, 'invalid search statistics')
      result
    end

    def indexes
      result = json_call('GET', '/v1/indexes')
      begin
        Validation.indexes!(result['indexes'])
      rescue ArgumentError
        raise ProtocolError, 'yamora: invalid index catalog', cause: nil
      end
      result
    end

    # Replaces the complete catalog. Revision guards concurrent catalog edits.
    def set_indexes(definitions, revision: nil)
      Validation.indexes!(definitions)
      headers = Validation.preconditions(revision)
      mutate { json_call('PUT', '/v1/indexes', value: { 'indexes' => definitions }, headers: headers, write: true, require_body_revision: true) }
    end

    def start_index_build(definitions, revision: nil)
      Validation.indexes!(definitions)
      headers = Validation.preconditions(revision)
      mutate { index_job('POST', '/v1/index-builds', value: { 'indexes' => definitions }, headers: headers, write: true, statuses: [202]) }
    end

    def index_build(id = nil)
      job_id!(id) if id
      index_job('GET', id ? "/v1/index-builds/#{id}" : '/v1/index-builds', expected_id: id)
    end

    def cancel_index_build(id)
      job_id!(id)
      mutate { index_job('DELETE', "/v1/index-builds/#{id}", expected_id: id, write: true, statuses: [202]) }
    end

    def transaction(operations, revision: nil)
      Validation.optional_revision!(revision)
      Validation.operations!(operations)
      spec = { 'operations' => operations }
      spec['revision'] = revision if revision
      mutate do
        result = json_call('POST', '/v1/transactions', value: spec, write: true, request_maximum: MAX_REQUEST_BYTES, require_body_revision: true)
        protocol!(result['status'] == 'committed' && result['operations'] == operations.size, 'invalid transaction receipt')
        result
      end
    end

    # One finite page only; no polling, reconnection, implicit progress or apply.
    def changes(after: nil, limit: 100)
      Validation.integer!(limit, 1, 100)
      Validation.require!(Validation.matches?(after, CHANGE_TOKEN), 'invalid change token') if after
      path = after ? "/v1/changes?after=#{after}&limit=#{limit}" : '/v1/changes'
      result = json_call('GET', path, require_body_revision: true)
      validate_changes(result, after, limit)
      result
    end

    def replication_status
      result = json_call('GET', '/v1/replication/status', require_body_revision: true)
      valid_position = (result['status'] == 'uninitialized' && result['after'].nil?) || (result['status'] == 'following' && Validation.matches?(result['after'], CHANGE_TOKEN))
      protocol!(result.key?('after') && valid_position, 'invalid replica status')
      result
    end

    private

    def document_path(collection, document)
      Validation.identifier!(collection)
      Validation.identifier!(document)
      "/v1/collections/#{collection}/documents/#{document}"
    end

    def protocol!(condition, message)
      raise ProtocolError, "yamora: #{message}" unless condition
    end

    def check_revision(actual, expected = nil)
      raise RevisionError, 'yamora: missing, invalid or changed revision' unless Validation.matches?(actual, REVISION) && (expected.nil? || actual == expected)
      actual
    end

    def response_text(body)
      text = body.dup.force_encoding(Encoding::UTF_8)
      protocol!(text.valid_encoding?, 'invalid UTF-8 response')
      text
    end

    def check_media(headers, allowed)
      protocol!(allowed.include?((headers['content-type'] || '').split(';', 2).first.to_s.strip.downcase), 'unexpected content type')
    end

    def json_call(method, path, value: nil, raw_body: nil, content_type: 'application/json', headers: {},
                  write: false, statuses: [200], expected_revision: nil, request_maximum: 2 * 1024 * 1024,
                  require_body_revision: false, job_revision: false)
      body = raw_body || (Validation.encode(value, request_maximum) unless value.nil?)
      payload, response = @transport.request(method, path, body: body, content_type: body && content_type,
                                             headers: headers, write: write, statuses: statuses)
      check_media(response, ['application/json'])
      revision = check_revision(response['x-yamldb-revision'], expected_revision)
      begin
        result = JSON.parse(response_text(payload), max_nesting: 64, create_additions: false, allow_nan: false, allow_duplicate_key: false)
      rescue JSON::ParserError, EncodingError, ArgumentError
        raise ProtocolError, 'yamora: invalid JSON response', cause: nil
      end
      protocol!(result.is_a?(Hash), 'expected JSON object')
      protocol!(finite_numbers?(result), 'JSON number exceeds finite Ruby Float range')
      unless job_revision
        check_revision(result['revision'], revision) if require_body_revision || result.key?('revision')
        result['revision'] = revision unless result.key?('revision')
      end
      result
    end

    # allow_nan: false rejects NaN/Infinity literals, but an ordinary exponent
    # can still overflow Ruby Float, including inside typed document values.
    def finite_numbers?(value)
      case value
      when Float
        value.finite?
      when Array
        value.all? { |item| finite_numbers?(item) }
      when Hash
        value.each_value.all? { |item| finite_numbers?(item) }
      else
        true
      end
    end

    def mutate
      yield
    rescue Error => error
      error.mark_uncertain! unless error.is_a?(HTTPError) && error.status.between?(400, 499) && error.status != 408
      raise error, cause: nil
    end

    def stored!(result, collection, document)
      protocol!(result['status'] == 'stored' && Validation.matches?(result['etag'], REVISION) && result['collection'] == collection && result['document'] == document, 'invalid mutation receipt')
      result
    end

    def names?(value, limit)
      value.is_a?(Array) && value.size <= limit && value.all? { |id| Validation.matches?(id, IDENTIFIER) } && value.each_cons(2).all? { |a, b| a < b }
    end

    def uint?(value)
      value.is_a?(Integer) && value.between?(0, 2**64 - 1)
    end

    def continuation!(after, revision)
      Validation.optional_revision!(revision)
      return unless after
      Validation.identifier!(after)
      Validation.require!(!revision.nil?, 'continuation requires revision')
    end

    def query_spec(spec)
      Validation.require!(spec.is_a?(Hash) && (spec.keys - %w[filter sort projection limit after revision count_only explain include_count]).empty?, 'invalid query fields')
      continuation!(spec['after'], spec['revision'])
      Validation.integer!(spec['limit'], 1, 1000) if spec.key?('limit')
      %w[count_only explain include_count].each { |key| Validation.boolean!(spec[key]) if spec.key?(key) }
      Validation.require!(!spec['after'] || !spec['count_only'], 'count continuation unavailable')
      Validation.require!(spec['filter'].is_a?(Hash), 'filter must be an object') if spec.key?('filter')
      if spec.key?('sort')
        sort = spec['sort']
        Validation.require!(sort.is_a?(Hash) && sort.size.between?(1, 8), 'invalid sort')
        sort.each do |path, direction|
          Validation.utf8!(path, 1024, nonempty: true)
          Validation.require!([1, -1, 'asc', 'desc', 'ascending', 'descending'].include?(direction), 'invalid sort direction')
        end
      end
      if spec.key?('projection')
        paths = spec['projection']
        Validation.require!(paths.is_a?(Array) && paths.size <= 64 && paths.uniq.size == paths.size, 'invalid projection')
        paths.each { |path| Validation.utf8!(path, 1024, nonempty: true) }
      end
      spec
    end

    def job_id!(id)
      Validation.require!(Validation.matches?(id, /\A[0-9a-f]{32}\z/), 'invalid index job ID')
    end

    def index_job(method, path, expected_id: nil, **options)
      # Job publication revision may precede the current database head.
      result = json_call(method, path, **options, job_revision: true)
      protocol!(%w[id status phase documents_scanned transactions_replayed revision error cancel_requested].all? { |key| result.key?(key) }, 'incomplete index job')
      status = result['status']
      protocol!(%w[idle running succeeded failed cancelled].include?(status) && %w[idle scanning catching_up publishing done].include?(result['phase']), 'invalid index job state')
      protocol!(Validation.matches?(result['id'], /\A[0-9a-f]{32}\z/) || (status == 'idle' && result['id'] == ''), 'invalid index job ID')
      protocol!(expected_id.nil? || expected_id == result['id'], 'changed index job ID')
      protocol!(uint?(result['documents_scanned']) && uint?(result['transactions_replayed']) && [true, false].include?(result['cancel_requested']), 'invalid index job counters')
      protocol!(%w[cancelled deadline_exceeded unique_constraint history_unavailable build_failed worker_unavailable publication_failed].include?(result['error']) || result['error'] == '', 'invalid index job error')
      protocol!(status == 'succeeded' ? Validation.matches?(result['revision'], REVISION) && result['error'] == '' : result['revision'] == '', 'invalid index job revision')
      protocol!(!%w[succeeded failed cancelled].include?(status) || result['phase'] == 'done', 'invalid terminal job phase')
      protocol!(status != 'running' || !%w[idle done].include?(result['phase']), 'invalid running job phase')
      result
    end

    def validate_changes(page, after, limit)
      next_after, checkpoint, oldest = page.values_at('next_after', 'checkpoint', 'oldest_after')
      protocol!([next_after, checkpoint, oldest].all? { |token| Validation.matches?(token, CHANGE_TOKEN) }, 'invalid feed tokens')
      protocol!(next_after[0, 36] == checkpoint[0, 36] && oldest[0, 36] == checkpoint[0, 36] && oldest <= next_after && next_after <= checkpoint && page['has_more'] == (next_after < checkpoint), 'invalid feed progress')
      protocol!(after.nil? || (after[0, 36] == checkpoint[0, 36] && after <= next_after), 'foreign feed progress')
      frames = page['transactions']
      protocol!(frames.is_a?(Array) && frames.size <= limit && (after || frames.empty?), 'invalid feed transactions')
      previous, revision = after, nil
      frames.each do |frame|
        protocol!(frame.is_a?(Hash) && Validation.matches?(frame['token'], CHANGE_TOKEN) && frame['token'][0, 36] == checkpoint[0, 36] && frame['token'] > previous && frame['token'] <= checkpoint, 'invalid feed frame token')
        check_revision(frame['previous_revision'], revision)
        check_revision(frame['revision'])
        protocol!([true, false].include?(frame['resnapshot_required']) && frame['operations'].is_a?(Array) && frame['operations'].size <= 256 && (!frame['resnapshot_required'] || frame['operations'].empty?), 'invalid feed frame')
        targets, bytes = [], 0
        frame['operations'].each do |op|
          protocol!(op.is_a?(Hash) && Validation.matches?(op['collection'], IDENTIFIER), 'invalid feed operation')
          key = [op['collection'], op['document']]
          protocol!(!targets.include?(key), 'duplicate feed target')
          targets << key
          if op.key?('document')
            protocol!(Validation.matches?(op['document'], IDENTIFIER) && ((op.keys.sort == %w[collection document put] && op['put'].is_a?(String) && !op['put'].empty?) || (op.keys.sort == %w[collection delete document] && op['delete'] == true)), 'invalid feed document')
            bytes += op.fetch('put', '').bytesize
          else
            protocol!(op.keys.sort == %w[collection create_collection] && op['create_collection'] == true, 'invalid feed collection')
          end
        end
        protocol!(bytes <= MAX_DOCUMENT_BYTES, 'feed source exceeds byte limit')
        previous, revision = frame.values_at('token', 'revision')
      end
      protocol!(frames.empty? ? (!page['has_more'] && (after.nil? || after == next_after)) : previous == next_after, 'incomplete feed progress')
    end
  end
end
