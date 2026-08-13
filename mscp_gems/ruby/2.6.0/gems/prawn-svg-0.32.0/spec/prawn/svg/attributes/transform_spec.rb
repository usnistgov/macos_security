require 'spec_helper'

describe Prawn::SVG::Attributes::Transform do
  class TransformTestElement
    include Prawn::SVG::Attributes::Transform

    attr_accessor :attributes, :warnings

    def initialize
      @warnings = []
      @attributes = {}
    end
  end

  let(:element) { TransformTestElement.new }

  subject { element.send :parse_transform_attribute_and_call }

  context "when a non-identity matrix is requested" do
    let(:transform) { 'translate(-5.5)' }

    it "passes the transform and executes the returned matrix" do
      expect(element).to receive(:parse_transform_attribute).with(transform).and_return([1, 2, 3, 4, 5, 6])
      expect(element).to receive(:add_call_and_enter).with('transformation_matrix', 1, 2, 3, 4, 5, 6)

      element.attributes['transform'] = transform
      subject
    end
  end

  context "when an identity matrix is requested" do
    let(:transform) { 'translate(0)' }

    it "does not execute any commands" do
      expect(element).to receive(:parse_transform_attribute).with(transform).and_return([1, 0, 0, 1, 0, 0])
      expect(element).not_to receive(:add_call_and_enter)

      element.attributes['transform'] = transform
      subject
    end
  end

  context "when transform is blank" do
    it "does nothing" do
      expect(element).not_to receive(:parse_transform_attribute)
      expect(element).not_to receive(:add_call_and_enter)

      subject
    end
  end
end
