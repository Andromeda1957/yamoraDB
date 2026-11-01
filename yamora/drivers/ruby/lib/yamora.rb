# frozen_string_literal: true

require 'net/http'
require 'json'
require 'openssl'
require 'timeout'

# Older JSON libraries silently ignore this option. Fail closed rather than
# silently accepting ambiguous response objects on an unqualified runtime.
begin
  JSON.parse('{"key":0,"key":1}', allow_duplicate_key: false)
  raise LoadError, 'yamora: bundled JSON must support allow_duplicate_key: false'
rescue JSON::ParserError
  # Supported by the tested Ruby 4.0 standard-library distribution.
end

require_relative 'yamora/validation'
require_relative 'yamora/transport'
require_relative 'yamora/client'
require_relative 'yamora/cluster'
require_relative 'yamora/binary_types'
require_relative 'yamora/binary_config'
require_relative 'yamora/binary_wire'
require_relative 'yamora/binary_reply'
require_relative 'yamora/binary_client'

require_relative 'yamora/binary_operations'
