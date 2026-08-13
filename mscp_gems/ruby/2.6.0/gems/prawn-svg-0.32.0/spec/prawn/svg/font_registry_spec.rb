require 'spec_helper'

RSpec.describe Prawn::SVG::FontRegistry do
  describe "#load" do
    let(:pdf) { Prawn::Document.new }
    let(:font_registry) { Prawn::SVG::FontRegistry.new(pdf.font_families) }

    it "matches a built in font" do
      font_registry.load("blah, 'courier', nothing").name.should == 'Courier'
    end

    it "matches a default font" do
      font_registry.load("serif").name.should == 'Times-Roman'
      font_registry.load("blah, serif").name.should == 'Times-Roman'
      font_registry.load("blah, serif , test").name.should == 'Times-Roman'
    end

    if Prawn::SVG::FontRegistry.new({}).installed_fonts["Verdana"]
      it "matches a font installed on the system" do
        font_registry.load("verdana, sans-serif").name.should == 'Verdana'
        font_registry.load("VERDANA, sans-serif").name.should == 'Verdana'
        font_registry.load("something, \"Times New Roman\", serif").name.should == "Times New Roman"
        font_registry.load("something, Times New Roman, serif").name.should == "Times New Roman"
      end
    else
      it "not running font test because we couldn't find Verdana installed on the system"
    end

    it "returns nil if it can't find any such font" do
      font_registry.load("blah, thing").should be_nil
      font_registry.load("").should be_nil
    end
  end

  describe "#installed_fonts" do
    let(:ttf)  { instance_double(Prawn::SVG::TTF, family: "Awesome Font", subfamily: "Italic") }
    let(:ttf2) { instance_double(Prawn::SVG::TTF, family: "Awesome Font", subfamily: "Regular") }
    before { Prawn::SVG::FontRegistry.external_font_families.clear }

    let(:pdf) do
      doc = Prawn::Document.new
      doc.font_families.update({
        "Awesome Font" => {:italic => "second.ttf", :normal => "file.ttf"}
      })
      doc
    end

    let(:font_registry) { Prawn::SVG::FontRegistry.new(pdf.font_families) }

    it "does not override existing entries in pdf when loading external fonts" do
      expect(Prawn::SVG::FontRegistry).to receive(:font_path).and_return(["x"])
      expect(Dir).to receive(:[]).with("x/**/*").and_return(["file.ttf", "second.ttf"])
      expect(Prawn::SVG::TTF).to receive(:new).with("file.ttf").and_return(ttf)
      expect(Prawn::SVG::TTF).to receive(:new).with("second.ttf").and_return(ttf2)
      expect(File).to receive(:file?).at_least(:once).and_return(true)

      Prawn::SVG::FontRegistry.load_external_fonts
      font_registry.installed_fonts

      existing_font = font_registry.installed_fonts["Awesome Font"]
      expect(existing_font).to eq(:italic => "second.ttf",:normal => "file.ttf")
    end
  end

  describe "::load_external_fonts" do
    let(:ttf)  { instance_double(Prawn::SVG::TTF, family: "Awesome Font", subfamily: "Italic") }
    let(:ttf2) { instance_double(Prawn::SVG::TTF, family: "Awesome Font", subfamily: "Regular") }

    before { Prawn::SVG::FontRegistry.external_font_families.clear }

    it "scans the font path and loads in some fonts" do
      expect(Prawn::SVG::FontRegistry).to receive(:font_path).and_return(["x"])
      expect(Dir).to receive(:[]).with("x/**/*").and_return(["file.ttf", "second.ttf"])
      expect(Prawn::SVG::TTF).to receive(:new).with("file.ttf").and_return(ttf)
      expect(Prawn::SVG::TTF).to receive(:new).with("second.ttf").and_return(ttf2)
      expect(File).to receive(:file?).at_least(:once).and_return(true)

      Prawn::SVG::FontRegistry.load_external_fonts

      result = Prawn::SVG::FontRegistry.external_font_families
      expect(result).to eq("Awesome Font" => {:italic => "file.ttf", :normal => "second.ttf"})
    end
  end
end
