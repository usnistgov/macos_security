require 'spec_helper'

RSpec.describe Prawn::SVG::TTF do
  subject { Prawn::SVG::TTF.new(filename) }

  context "with a truetype font" do
    let(:filename) { "#{File.dirname(__FILE__)}/../../sample_ttf/OpenSans-SemiboldItalic.ttf" }

    it "gets the English family and subfamily from the font file" do
      expect(subject.family).to eq 'Open Sans'
      expect(subject.subfamily).to eq 'Semibold Italic'
    end
  end

  context "with a file that isn't a TTF" do
    let(:filename) { __FILE__ }

    it "has a nil family and subfamily" do
      expect(subject.family).to be nil
      expect(subject.subfamily).to be nil
    end
  end

  context "with a file that doesn't exist" do
    let(:filename) { "does_not_exist" }

    it "has a nil family and subfamily" do
      expect(subject.family).to be nil
      expect(subject.subfamily).to be nil
    end
  end
end
