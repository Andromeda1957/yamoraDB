# frozen_string_literal: true

require_relative 'helper'

class ScratchTest < Minitest::Test
  include DriverFixtures

  def with_tmpdir(root)
    original = ENV['TMPDIR']
    root.nil? ? ENV.delete('TMPDIR') : ENV['TMPDIR'] = root
    yield
  ensure
    original.nil? ? ENV.delete('TMPDIR') : ENV['TMPDIR'] = original
  end

  def test_caller_root_and_existing_files_survive_success_and_failure_cleanup
    Dir.mktmpdir('caller-', ENV.fetch('TMPDIR')) do |caller_root|
      sentinel = File.join(caller_root, 'caller-owned.txt')
      File.write(sentinel, 'preserve caller data')
      allocations = []
      with_tmpdir(caller_root) do
        2.times do
          scratch do |directory|
            allocations << directory
            assert_equal File.realpath(caller_root), File.dirname(directory)
            File.write(File.join(directory, 'owned.txt'), 'disposable')
          end
          refute_path_exists allocations.last
        end
        error_class = Class.new(StandardError)
        assert_raises(error_class) do
          scratch do |directory|
            allocations << directory
            File.write(File.join(directory, 'failed.txt'), 'disposable')
            raise error_class, 'exercise failed-test cleanup'
          end
        end
        refute_path_exists allocations.last
      end
      assert_equal allocations.size, allocations.uniq.size
      assert_equal ['caller-owned.txt'], Dir.children(caller_root)
      assert_equal 'preserve caller data', File.read(sentinel)
    end
  end

  def test_unset_root_root_itself_files_and_escaping_symlinks_are_rejected
    Dir.mktmpdir('caller-', ENV.fetch('TMPDIR')) do |caller_root|
      file = File.join(caller_root, 'not-a-directory')
      File.write(file, 'preserve')
      escape = File.join(caller_root, 'escape')
      File.symlink('/var/tmp', escape)
      invalid = [nil, '/var/tmp/andromeda-work', '/var/tmp/andromeda-work/',
                 '/var/tmp/andromeda-work/../andromeda-work', '/var/tmp', '/',
                 File.join(caller_root, 'missing'), file, escape]
      if File.directory?('/dev/shm')
        memory = File.join(caller_root, 'memory')
        File.symlink('/dev/shm', memory)
        invalid << memory
      end
      invalid.each do |root|
        with_tmpdir(root) do
          assert_raises(ArgumentError, "invalid TMPDIR #{root.inspect}") do
            scratch { flunk 'invalid scratch root accepted' }
          end
        end
      end
      assert_equal 'preserve', File.read(file)
    end
  end
end
