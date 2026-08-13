require 'spec_helper'

RSpec.describe Prawn::SVG::CSS::FontFamilyParser do
  describe "#parse" do
    it "correctly handles quotes and escaping" do
      tests = {
        "" => [],
        "font" => ["font"],
        "font name, other font" => ["font name", "other font"],
        "'font name', other font" => ["font name", "other font"],
        "'font, name', other font" => ["font, name", "other font"],
        '"font name", other font' => ["font name", "other font"],
        '"font, name", other font' => ["font, name", "other font"],
        'weird \\" name' => ['weird " name'],
        'weird\\, name' => ["weird, name"],
        ' stupid , spacing ' => ["stupid", "spacing"],
      }

      tests.each do |string, expected|
        expect(Prawn::SVG::CSS::FontFamilyParser.parse(string)).to eq expected
      end
    end
  end
end
