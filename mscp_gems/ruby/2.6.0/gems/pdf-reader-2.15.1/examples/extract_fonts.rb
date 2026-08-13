#!/usr/bin/env ruby
# coding: utf-8

# This demonstrates a way to extract TTF fonts from a PDF. It could be expanded
# to support extra font formats if required. Be aware that many PDFs subset
# fonts before they're embedded so glyphs may be missing or re-arranged.

require 'pdf/reader'

module ExtractFonts

  class Extractor

    def page(page)
      count = 0

      return count if page.fonts.nil? || page.fonts.empty?

      page.fonts.each do |label, font|
        next if complete_refs[label]
        complete_refs[label] = true

        process_font(page, font)

        count += 1
      end

      count
    end

    private

    def process_font(page, font)
      font = page.objects.deref(font)

      case font[:Subtype]
      when :Type0 then
        font[:DescendantFonts].each { |f| process_font(page, f) }
      when :TrueType, :CIDFontType2 then
        ExtractFonts::TTF.new(page.objects, font).save("#{font[:BaseFont]}.ttf")
      else
        $stderr.puts "unsupported font type #{font[:Subtype]} for #{font[:BaseFont]}"
      end
    end

    def complete_refs
      @complete_refs ||= {}
    end

  end

  class TTF

    def initialize(objects, font)
      @objects, @font = objects, font
      @descriptor = @objects.deref(@font[:FontDescriptor])
    end

    def save(filename)
      puts "#{filename}"
      if @descriptor && @descriptor[:FontFile2]
        stream = @objects.deref(@descriptor[:FontFile2])
        File.open(filename, "wb") { |file| file.write stream.unfiltered_data }
      else
        $stderr.puts "- TTF font not embedded"
      end
    end
  end
end

if ARGV.size == 0 # default file name
  ARGV << File.expand_path(File.join(File.dirname(__dir__), "spec", "data", "cairo-unicode.pdf")) 
end

extractor = ExtractFonts::Extractor.new

ARGV.each do |arg|
  PDF::Reader.open(arg) do |reader|
    page = reader.page(1)
    extractor.page(page)
  end
end
