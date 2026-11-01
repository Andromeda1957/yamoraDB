# frozen_string_literal: true

# Cluster acceptance is mandatory in this runner; absent daemons never skip.
binary = ENV['YAMORA_TEST_BINARY']
unless binary && binary.start_with?('/') && File.executable?(binary)
  abort 'YAMORA_TEST_BINARY must name an absolute executable native daemon'
end

# All native fixtures, including existing HTTP/cluster acceptance, fail fatally.
ENV['ASAN_OPTIONS'] = 'detect_leaks=1:abort_on_error=1:halt_on_error=1'
ENV['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'

# Includes cluster routing, lifetime and native tests alongside standalone suites.
Dir[File.join(__dir__, 'test_*.rb')].sort.each { |file| require file }
