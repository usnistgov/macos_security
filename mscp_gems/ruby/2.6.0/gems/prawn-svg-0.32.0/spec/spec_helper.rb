require 'bundler'
Bundler.require(:default, :development)

# Requires supporting files with custom matchers and macros, etc,
# in ./support/ and its subdirectories.
Dir["#{File.dirname(__FILE__)}/support/**/*.rb"].each {|f| require f}

module Support
  def flatten_calls(calls)
    [].tap do |flattened_calls|
      add = -> (local_calls) do
        local_calls.each do |call|
          flattened_calls << call[0..2]
          add.call call[3]
        end
      end

      add.call element.base_calls
    end
  end

  def fake_state
    state = Prawn::SVG::State.new
    state.viewport_sizing = document.sizing if defined?(document)
    state
  end
end

RSpec.configure do |config|
  config.mock_with :rspec do |c|
    c.syntax = [:should, :expect]
  end

  config.expect_with :rspec do |c|
    c.syntax = [:should, :expect]
  end

  config.include Support
end
