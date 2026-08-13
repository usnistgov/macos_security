# encoding: utf-8
#
# Copyright October 2014, Jesse Doyle. All rights reserved.
#
# This is free software. Please see the LICENSE and COPYING files for details.

module ParserHelper
  def tokenize_string(string)
    regex = Prawn::Icon::Parser::PARSER_REGEX
    string.scan(regex)
  end

  def contentize_string(string)
    regex = Prawn::Icon::Parser::CONTENT_REGEX
    string.scan(regex).flatten
  end
end
