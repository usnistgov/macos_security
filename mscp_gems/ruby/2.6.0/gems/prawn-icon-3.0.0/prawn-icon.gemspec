basedir = File.expand_path(File.dirname(__FILE__))
require "#{basedir}/lib/prawn/icon/version"

Gem::Specification.new do |spec|
  spec.name     = 'prawn-icon'
  spec.version  = Prawn::Icon::VERSION
  spec.platform = Gem::Platform::RUBY
  spec.summary  = 'Provides icon fonts for PrawnPDF'
  spec.files    =  Dir.glob('{lib,spec,data,examples}/**/**/*') +
                   %w[prawn-icon.gemspec Gemfile Rakefile] +
                   %w[README.md CHANGELOG.md] +
                   %w[COPYING LICENSE GPLv2 GPLv3]

  spec.require_path              = 'lib'
  spec.required_ruby_version     = '>= 1.9.3'
  spec.required_rubygems_version = '>= 1.3.6'

  spec.homepage = 'https://github.com/jessedoyle/prawn-icon/'

  spec.test_files = Dir['spec/*_spec.rb']
  spec.authors    = ['Jesse Doyle']
  spec.email      = ['jdoyle@ualberta.ca']
  spec.licenses   = ['RUBY', 'GPL-2', 'GPL-3']

  spec.add_dependency('prawn', '>= 1.1.0', '< 3.0.0')

  spec.add_development_dependency('pdf-inspector', '>= 1.2.1')
  spec.add_development_dependency('rspec', '>= 3.5.0')
  spec.add_development_dependency('rubocop', '~> 0.49.1')
  spec.add_development_dependency('rake')
  spec.add_development_dependency('pdf-reader', '>= 1.4')
  spec.add_development_dependency('simplecov')

  spec.description = <<-END_DESC
  Prawn::Icon provides various icon fonts including
  FontAwesome, PaymentFont and Foundation Icons
  for use with the Prawn PDF toolkit.
  END_DESC
end
