# encoding: utf-8
#
# Copyright October 2014, Jesse Doyle. All rights reserved.
#
# This is free software. Please see the LICENSE and COPYING files for details.

module PDFHelper
  def create_pdf
    Prawn::Document.new(margin: 0)
  end

  def valid_unicode?(string)
    string.force_encoding('UTF-8').valid_encoding?
  end
end
