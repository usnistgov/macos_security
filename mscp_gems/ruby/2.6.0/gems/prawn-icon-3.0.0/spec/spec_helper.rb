# encoding: utf-8
#
# Copyright October 2014, Jesse Doyle. All rights reserved.
#
# This is free software. Please see the LICENSE and COPYING files for details.
#
#
require 'simplecov'
SimpleCov.start

require "bundler"
Bundler.setup

require "prawn/icon"
require 'pdf/inspector'
require "rspec"

# Requires supporting ruby files with custom matchers and macros, etc,
# in spec/extensions/ and its subdirectories.
Dir[File.dirname(__FILE__) + "/support/**/*.rb"].each { |f| require f }

RSpec.configure do |config|
  config.include PDFHelper
  config.include ParserHelper
end