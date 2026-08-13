require 'spec_helper'

RSpec.describe Prawn::SVG::Properties do
  subject { Prawn::SVG::Properties.new }

  describe "#load_default_stylesheet" do
    it "loads in the defaults and returns self" do
      expect(subject.load_default_stylesheet).to eq subject
      expect(subject.font_family).to eq 'sans-serif'
    end
  end

  describe "#set" do
    it "sets a property" do
      result = subject.set('color', 'red')
      expect(result).to be
      expect(subject.color).to eq 'red'
    end

    it "handles property names that are not lower case" do
      result = subject.set('COLor', 'red')
      expect(result).to be
      expect(subject.color).to eq 'red'
    end

    it "right-cases and strips keywords" do
      subject.set('stroke-linecap', ' Round ')
      expect(subject.stroke_linecap).to eq 'round'
    end

    it "doesn't right-case values that aren't recognised as keywords" do
      subject.set('color', 'Red')
      expect(subject.color).to eq 'Red'
    end

    it "sets a 'keyword restricted' property to its default if the value doesn't match a keyword" do
      subject.set('stroke-linecap', 'invalid')
      expect(subject.stroke_linecap).to eq 'butt'
    end
  end

  describe "#load_hash" do
    it "uses #set to load in a hash of properties" do
      subject.load_hash("stroke" => "blue", "fill" => "green", 'stroke-linecap' => "Round")
      expect(subject.stroke).to eq 'blue'
      expect(subject.fill).to eq 'green'
      expect(subject.stroke_linecap).to eq 'round'
    end
  end

  describe "#compute_properties" do
    let(:other) { Prawn::SVG::Properties.new }

    it "auto-inherits inheritable properties when the property is not supplied" do
      subject.set('color', 'green')
      subject.compute_properties(other)
      expect(subject.color).to eq 'green'
    end

    it "doesn't auto-inherit non-inheritable properties" do
      subject.set('display', 'none')
      subject.compute_properties(other)
      expect(subject.display).to eq 'inline'
    end

    it "inherits non-inheritable properties when specifically asked to" do
      subject.set('display', 'none')
      other.set('display', 'inherit')
      subject.compute_properties(other)
      expect(subject.display).to eq 'none'
    end

    it "uses the new property value" do
      subject.set('color', 'green')
      other.set('color', 'red')
      subject.compute_properties(other)
      expect(subject.color).to eq 'red'
    end

    describe "font size" do
      before do
        subject.font_size = "15"
        other.font_size = font_size
      end

      context "when given a % as a font-size" do
        let(:font_size) { "120%" }

        it "calculates the new font size" do
          subject.compute_properties(other)
          expect(subject.font_size).to eq "18.0"
        end
      end

      context "when given 'larger' as a font-size" do
        let(:font_size) { "larger" }

        it "calculates the new font size" do
          subject.compute_properties(other)
          expect(subject.font_size).to eq "19.0"
        end
      end

      context "when given 'smaller' as a font-size" do
        let(:font_size) { "smaller" }

        it "calculates the new font size" do
          subject.compute_properties(other)
          expect(subject.font_size).to eq "11.0"
        end
      end

      context "when given a value in 'em' as a font-size" do
        let(:font_size) { "2.5em" }

        it "calculates the new font size" do
          subject.compute_properties(other)
          expect(subject.font_size).to eq "37.5"
        end
      end

      context "when given a value in 'rem' as a font-size" do
        let(:font_size) { "2.5rem" }

        it "calculates the new font size" do
          subject.compute_properties(other)
          expect(subject.font_size).to eq "40.0"
        end
      end

      context "when given a value in 'px' as a font-size" do
        let(:font_size) { "19.5px" }

        it "uses the font size specified" do
          subject.compute_properties(other)
          expect(subject.font_size).to eq "19.5"
        end
      end

      context "when given a value in 'pt' as a font-size" do
        let(:font_size) { "19.5pt" }

        it "uses the font size specified" do
          subject.compute_properties(other)
          expect(subject.font_size).to eq "19.5"
        end
      end

      context "when given a value without units as a font-size" do
        let(:font_size) { "19.5" }

        it "uses the font size specified" do
          subject.compute_properties(other)
          expect(subject.font_size).to eq "19.5"
        end
      end

      context "when given the keyword 'inherit' as a font-size" do
        let(:font_size) { "inherit" }

        it "uses the font size specified by the parent" do
          subject.compute_properties(other)
          expect(subject.font_size).to eq "15"
        end
      end
    end
  end

  describe "#numerical_font_size" do
    context "when the font size is a number" do
      before { subject.font_size = "16.5" }

      it "returns the number as a float" do
        expect(subject.numerical_font_size).to eq 16.5
      end
    end

    context "when the font size is one of the keyword size specifiers" do
      before { subject.font_size = "x-large" }

      it "returns the font size number corresponding with the keyword" do
        expect(subject.numerical_font_size).to eq 24
      end
    end
  end
end
