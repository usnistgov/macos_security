require File.dirname(__FILE__) + '/../../spec_helper'

describe Prawn::SVG::Document do
  let(:bounds) { [100, 100] }
  let(:options) { {} }

  describe "#initialize" do
    context "when unparsable XML is provided" do
      let(:svg) { "this isn't SVG data" }

      it "raises an exception" do
        expect {
          Prawn::SVG::Document.new(svg, bounds, options)
        }.to raise_error Prawn::SVG::Document::InvalidSVGData, "The data supplied is not a valid SVG document."
      end
    end

    context "when the user passes in a filename instead of SVG data" do
      let(:svg) { "some_file.svg" }

      it "raises an exception letting them know what they've done" do
        expect {
          Prawn::SVG::Document.new(svg, bounds, options)
        }.to raise_error Prawn::SVG::Document::InvalidSVGData, "The data supplied is not a valid SVG document.  It looks like you've supplied a filename instead; use IO.read(filename) to get the data before you pass it to prawn-svg."
      end
    end
  end
end
