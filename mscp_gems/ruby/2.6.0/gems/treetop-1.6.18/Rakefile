require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require File.expand_path("../lib/treetop/version", __FILE__)

task :default => :spec
RSpec::Core::RakeTask.new do |t|
  t.pattern = 'spec/**/*spec.rb'
  # t.libs << 'spec' # @todo not sure what this did in the original rspec 1.3
end

task :spec => 'lib/treetop/compiler/metagrammar.treetop'
file 'lib/treetop/compiler/metagrammar.treetop' do |t|
  unless $bootstrapped_gen_1_metagrammar
    load File.expand_path('../lib/treetop/bootstrap_gen_1_metagrammar.rb', __FILE__)
  end

  Treetop::Compiler::GrammarCompiler.new.compile(METAGRAMMAR_PATH)
end

task :rebuild do
  $:.unshift "lib"
  require './lib/treetop'
  load File.expand_path('../lib/treetop/compiler/metagrammar.rb', __FILE__)
  Treetop::Compiler::GrammarCompiler.new.compile('lib/treetop/compiler/metagrammar.treetop')
end

task :version do
  puts 'Ruby is '+RUBY_VERSION
  puts 'Treetop is '+Treetop::VERSION::STRING
end

desc 'Generate and upload website files'
task :website do
  system <<-END
    rm -rf .doc-tmp
    cp -r doc .doc-tmp
    git checkout gh-pages
    rm -r doc
    mv .doc-tmp doc
    rake website upload
    git checkout master
  END
end
