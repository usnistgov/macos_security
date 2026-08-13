require File.dirname(__FILE__) + '/../../spec_helper'

describe Prawn::SVG::Font do
  describe "#initialize" do
    it "maps generic font name to built-in font" do
      font_registry = Prawn::SVG::FontRegistry.new({})
      font = Prawn::SVG::Font.new('sans-serif', :normal, :normal, font_registry: font_registry)
      font.name.should == 'Helvetica'
    end

    it "preserves generic font name if mapped" do
      font_registry = Prawn::SVG::FontRegistry.new('sans-serif' => { normal: 'Times-Roman' })
      font = Prawn::SVG::Font.new('sans-serif', :normal, :normal, font_registry: font_registry)
      font.name.should == 'sans-serif'
    end
  end
end
