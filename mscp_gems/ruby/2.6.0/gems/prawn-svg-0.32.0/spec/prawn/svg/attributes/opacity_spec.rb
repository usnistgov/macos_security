require 'spec_helper'

describe Prawn::SVG::Attributes::Opacity do
  class OpacityTestElement
    include Prawn::SVG::Attributes::Opacity

    attr_accessor :properties, :state

    def initialize
      @properties = ::Prawn::SVG::Properties.new
      @state = ::Prawn::SVG::State.new
    end

    def clamp(value, min_value, max_value)
      [[value, min_value].max, max_value].min
    end
  end

  let(:element) { OpacityTestElement.new }

  describe "#parse_opacity_attributes_and_call" do
    subject { element.parse_opacity_attributes_and_call }

    context "with no opacity specified" do
      it "does nothing" do
        expect(element).not_to receive(:add_call_and_enter)
        subject
      end
    end

    context "with opacity" do
      it "sets fill and stroke opacity" do
        element.properties.opacity = '0.4'

        expect(element).to receive(:add_call_and_enter).with('transparent', 0.4, 0.4)
        subject

        expect(element.state.fill_opacity).to eq 0.4
        expect(element.state.stroke_opacity).to eq 0.4
      end
    end

    context "with just fill opacity" do
      it "sets fill opacity and sets stroke opacity to 1" do
        element.properties.fill_opacity = '0.4'

        expect(element).to receive(:add_call_and_enter).with('transparent', 0.4, 1)
        subject

        expect(element.state.fill_opacity).to eq 0.4
        expect(element.state.stroke_opacity).to eq 1
      end
    end

    context "with an existing fill/stroke opacity" do
      it "multiplies the new opacity by the old" do
        element.state.fill_opacity = 0.5
        element.state.stroke_opacity = 0.8

        element.properties.fill_opacity = '0.4'
        element.properties.stroke_opacity = '0.5'

        expect(element).to receive(:add_call_and_enter).with('transparent', 0.2, 0.4)
        subject

        expect(element.state.fill_opacity).to eq 0.2
        expect(element.state.stroke_opacity).to eq 0.4
      end
    end

    context "with stroke, fill, and opacity all specified" do
      it "choses the lower of them" do
        element.properties.fill_opacity = '0.4'
        element.properties.stroke_opacity = '0.6'
        element.properties.opacity = '0.5'

        expect(element).to receive(:add_call_and_enter).with('transparent', 0.4, 0.5)
        subject

        expect(element.state.fill_opacity).to eq 0.4
        expect(element.state.stroke_opacity).to eq 0.5
      end
    end
  end
end
