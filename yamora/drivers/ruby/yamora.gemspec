# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = 'yamora'
  spec.version = '0.1.0'
  spec.summary = 'Source-preserving Yamora HTTP, replica-set and binary TLS clients'
  spec.authors = ['Christian Walls']
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 4.0'
  spec.files = Dir.glob('lib/**/*.rb', base: __dir__).sort +
               %w[README.md LICENSE examples/crud.rb]
  spec.require_paths = ['lib']
  # These are existing library requirements, including bundled/default gems.
  spec.add_dependency 'json', '>= 2.18.0', '< 3'
  %w[net-http openssl timeout securerandom].each { |name| spec.add_dependency name }
end
