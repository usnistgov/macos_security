require 'spec_helper'

describe Prawn::SVG::Calculators::Pixels do
  class TestPixelsCalculator
    include Prawn::SVG::Calculators::Pixels

    def computed_properties
      Struct.new(:numerical_font_size).new(16)
    end

    [:x, :y, :pixels, :x_pixels, :y_pixels].each { |method| public method }
  end

  let(:viewport_sizing) do
    instance_double(Prawn::SVG::Calculators::DocumentSizing, viewport_width: 600, viewport_height: 400, viewport_diagonal: 500, :requested_width= => nil, :requested_height= => nil)
  end

  let(:document_sizing) do
    instance_double(Prawn::SVG::Calculators::DocumentSizing, output_height: 800)
  end

  let(:state) { instance_double(Prawn::SVG::State, viewport_sizing: viewport_sizing) }
  let(:document) { instance_double(Prawn::SVG::Document, sizing: document_sizing) }

  subject { TestPixelsCalculator.new }

  before do
    allow(subject).to receive(:state).and_return(state)
    allow(subject).to receive(:document).and_return(document)
  end

  describe "#pixels" do
    it "converts a variety of measurement units to points" do
      expect(subject.pixels(32)).to eq 32.0
      expect(subject.pixels(32.0)).to eq 32.0
      expect(subject.pixels("32")).to eq 32.0
      expect(subject.pixels("32unknown")).to eq 32.0
      expect(subject.pixels("32px")).to eq 32.0
      expect(subject.pixels("32pt")).to eq 32.0
      expect(subject.pixels("32in")).to eq 32.0 * 72
      expect(subject.pixels("32pc")).to eq 32.0 * 15
      expect(subject.pixels("4em")).to eq 4 * 16
      expect(subject.pixels("4ex")).to eq 4 * 8
      expect(subject.pixels("32mm")).to be_within(0.0001).of(32 * 72 * 0.0393700787)
      expect(subject.pixels("32cm")).to be_within(0.0001).of(32 * 72 * 0.393700787)
      expect(subject.pixels("50%")).to eq 250
    end
  end

  describe "#x_pixels" do
    it "uses the viewport width for percentages" do
      expect(subject.x_pixels("50")).to eq 50
      expect(subject.x_pixels("50%")).to eq 300
    end
  end

  describe "#y_pixels" do
    it "uses the viewport height for percentages" do
      expect(subject.y_pixels("50")).to eq 50
      expect(subject.y_pixels("50%")).to eq 200
    end
  end

  describe "#x" do
    it "performs the same as #x_pixels" do
      expect(subject.x("50")).to eq 50
      expect(subject.x("50%")).to eq 300
    end
  end

  describe "#y" do
    it "performs the same as #y_pixels but subtracts the pixels from the page height" do
      expect(subject.y("50")).to eq 800 - 50
      expect(subject.y("50%")).to eq 800 - 200
    end
  end
end
