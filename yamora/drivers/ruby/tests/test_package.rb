# frozen_string_literal: true

require_relative 'helper'
require 'open3'
require 'rbconfig'
require 'rubygems/package'

class PackageTest < Minitest::Test
  include DriverFixtures

  def command(env, *args, chdir:)
    output, status = Open3.capture2e(env, *args, chdir: chdir)
    assert status.success?, output
    output
  end

  def test_installed_gem_and_native_mtls_example
    raise 'YAMORA_TEST_BINARY required' unless ENV['YAMORA_TEST_BINARY']
    scratch do |dir|
      root = File.expand_path('..', __dir__)
      stage = File.join(dir, 'source')
      Dir.mkdir(stage)
      %w[lib examples README.md LICENSE yamora.gemspec].each { |name| FileUtils.cp_r(File.join(root, name), stage) }
      artifact = File.join(dir, 'yamora-0.1.0.gem')
      gem = File.join(RbConfig::CONFIG.fetch('bindir'), 'gem')
      command({}, RbConfig.ruby, gem, 'build', 'yamora.gemspec', '--output', artifact, chdir: stage)
      package = Gem::Package.new(artifact)
      expected = Dir.glob('lib/**/*.rb', base: root).sort + %w[README.md LICENSE examples/crud.rb]
      assert_equal expected.sort, package.spec.files.sort
      assert_equal '0.1.0', package.spec.version.to_s
      assert_equal 'MIT', package.spec.license

      home = File.join(dir, 'consumer-gems')
      env = { 'GEM_HOME' => home, 'GEM_PATH' => [home, Gem.default_dir].join(File::PATH_SEPARATOR),
              'RUBYLIB' => nil, 'RUBYOPT' => nil }
      command(env, RbConfig.ruby, gem, 'install', '--local', artifact, '--no-document', chdir: dir)
      probe = <<~'RUBY'
        require 'yamora'
        spec = Gem.loaded_specs.fetch('yamora')
        abort 'wrong package origin' unless spec.full_gem_path.start_with?(ENV.fetch('GEM_HOME') + '/')
        %w[Client ClusterClient BinaryClient BinaryConfig BinaryResponse].each { |name| Yamora.const_get(name) }
        abort 'source-tree import' unless $LOADED_FEATURES.grep(%r{/yamora(?:/|\.rb)}).all? { |file| file.start_with?(spec.full_gem_path + '/') }
        puts spec.full_gem_path
      RUBY
      installed = command(env, RbConfig.ruby, '-e', probe, chdir: dir).strip
      certificates(dir)
      flags = %w[--tls-cert-file server.pem --tls-key-file server.key --tls-client-ca-file ca.pem]
      flags = flags.each_slice(2).flat_map { |flag, file| [flag, File.join(dir, file)] }
      with_native(dir, flags: flags) do |_client, port|
        example_env = env.merge('YAMORA_PORT' => port.to_s, 'YAMORA_CA_FILE' => File.join(dir, 'ca.pem'),
          'YAMORA_CLIENT_CERT_FILE' => File.join(dir, 'client.pem'), 'YAMORA_CLIENT_KEY_FILE' => File.join(dir, 'client.key'),
          'YAMORA_READ_TOKEN' => READ_TOKEN, 'YAMORA_WRITE_TOKEN' => WRITE_TOKEN)
        assert_equal "CRUD_OK\n", command(example_env, RbConfig.ruby, File.join(installed, 'examples/crud.rb'), chdir: dir)
      end
    end
  end
end
