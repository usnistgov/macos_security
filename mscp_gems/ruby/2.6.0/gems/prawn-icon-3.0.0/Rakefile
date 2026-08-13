# encoding: utf-8
#
# Copyright October 2014, Jesse Doyle. All rights reserved.
#
# This is free software. Please see the LICENSE and COPYING files for details.

require 'bundler'
Bundler.setup

require 'rake'
require 'rspec/core/rake_task'
require 'rubocop/rake_task'

task :default => [:spec, :rubocop]

desc 'Run all rspec files'
RSpec::Core::RakeTask.new('spec') do |c|
  c.rspec_opts = '-t ~unresolved'
end

desc 'Generate the legend documents for all icon fonts.'
task :legend do
  example = File.join(File.dirname(__FILE__), 'examples', '*.rb')
  files = Dir[example]
  files.reject! { |f| File.basename(f) == 'example_helper.rb' }
  files.each do |file|
    puts "Generating from: #{file}"
    require file
  end
  puts 'All Done!'
end

RuboCop::RakeTask.new
