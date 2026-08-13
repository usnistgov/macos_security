require 'spec_helper'

RSpec.describe Prawn::SVG::TransformParser do
  class Test
    include Prawn::SVG::Calculators::Pixels
    include Prawn::SVG::TransformParser

    State = Struct.new(:viewport_sizing)
    Properties = Struct.new(:numerical_font_size)
    Document = Struct.new(:sizing)

    def document
      Document.new(_sizing)
    end

    def state
      State.new(_sizing)
    end

    def computed_properties
      Properties.new(14)
    end

    def _sizing
      Prawn::SVG::Calculators::DocumentSizing.new([1000, 800])
    end
  end

  subject { Test.new.parse_transform_attribute(transform) }

  context "with no transform" do
    let(:transform) { '' }
    it { is_expected.to eq [1, 0, 0, 1, 0, 0] }
  end

  context "with translate" do
    let(:transform) { 'translate(10 20)' }
    it { is_expected.to eq [1, 0, 0, 1, 10, -20] }
  end

  context "with single argument translate" do
    let(:transform) { 'translate(10)' }
    it { is_expected.to eq [1, 0, 0, 1, 10, 0] }
  end

  context "with translateX" do
    let(:transform) { 'translateX(10)' }
    it { is_expected.to eq [1, 0, 0, 1, 10, 0] }
  end

  context "with translateY" do
    let(:transform) { 'translateY(10)' }
    it { is_expected.to eq [1, 0, 0, 1, 0, -10] }
  end

  let(:sin30) { Math.sin(30 * Math::PI / 180.0) }
  let(:cos30) { Math.cos(30 * Math::PI / 180.0) }
  let(:tan30) { Math.tan(30 * Math::PI / 180.0) }

  context "with single argument rotate" do
    let(:transform) { 'rotate(30)' }
    it { is_expected.to eq [cos30, -sin30, sin30, cos30, 0, 0] }
  end

  context "with triple argument rotate" do
    let(:transform) { 'rotate(30 100 200)' }
    it { is_expected.to eq [cos30, -sin30, sin30, cos30, 113.39745962155611, 23.205080756887753] }
  end

  context "with scale" do
    let(:transform) { 'scale(1.5)' }
    it { is_expected.to eq [1.5, 0, 0, 1.5, 0, 0] }
  end

  context "with skewX" do
    let(:transform) { 'skewX(30)' }
    it { is_expected.to eq [1, 0, -tan30, 1, 0, 0] }
  end

  context "with skewY" do
    let(:transform) { 'skewY(30)' }
    it { is_expected.to eq [1, -tan30, 0, 1, 0, 0] }
  end

  context "with matrix" do
    let(:transform) { 'matrix(1 2 3 4 5 6)' }
    it { is_expected.to eq [1, -2, -3, 4, 5, -6] }
  end

  context "with multiple" do
    let(:transform) { 'scale(2) translate(7) scale(3)' }
    it { is_expected.to eq [6, 0, 0, 6, 14, 0] }
  end
end
