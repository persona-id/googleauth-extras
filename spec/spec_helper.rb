# frozen_string_literal: true

require 'bundler/setup'
Bundler.require

require 'webmock/rspec'

Dir[File.join(File.expand_path(__dir__), 'support', '**', '*.rb')].sort.each { |f| require f }

RSpec.configure do |config|
  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = '.rspec_status'

  config.expect_with :rspec do |c|
    c.syntax = :expect
    c.max_formatted_output_length = 1024
  end
end
