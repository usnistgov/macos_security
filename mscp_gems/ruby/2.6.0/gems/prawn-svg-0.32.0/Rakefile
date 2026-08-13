#!/usr/bin/env rake

require 'bundler/gem_tasks'

begin
  require 'rdoc/task'
rescue LoadError
  require 'rdoc/rdoc'
  require 'rake/rdoctask'
  RDoc::Task = Rake::RDocTask
end

RDoc::Task.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = 'prawn-svg documentation'
  rdoc.options << '--line-numbers'
  rdoc.rdoc_files.include('README')
  rdoc.rdoc_files.include('lib/**/*.rb')
end

require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec) do |spec|
end

task :default => :spec
