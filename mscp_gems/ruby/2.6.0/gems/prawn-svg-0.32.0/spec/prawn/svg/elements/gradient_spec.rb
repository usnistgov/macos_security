require 'spec_helper'

describe Prawn::SVG::Elements::Gradient do
  let(:document) { Prawn::SVG::Document.new(svg, [800, 600], {width: 800, height: 600}) }
  let(:element)  { Prawn::SVG::Elements::Gradient.new(document, document.root, [], fake_state) }

  before do
    allow(element).to receive(:assert_compatible_prawn_version)
    element.process
  end

  describe "object bounding box with linear gradient" do
    let(:svg) do
      <<-SVG
        <linearGradient id="flag" x1="0" x2="0.2" y1="0" y2="1">
          <stop offset="25%" stop-color="red"/>
          <stop offset="50%" stop-color="white"/>
          <stop offset="75%" stop-color="blue"/>
        </linearGradient>
      SVG
    end

    it "is stored in the document gradients table" do
      expect(document.gradients["flag"]).to eq element
    end

    it "returns correct gradient arguments for an element" do
      arguments = element.gradient_arguments(double(bounding_box: [100, 100, 200, 0]))
      expect(arguments).to eq(
        from: [100.0, 100.0],
        to:   [120.0, 0.0],
        stops: [[0, "ff0000"], [0.25, "ff0000"], [0.5, "ffffff"], [0.75, "0000ff"], [1, "0000ff"]],
        apply_transformations: true,
      )
    end

    it "returns nil if the element doesn't have a bounding box" do
      arguments = element.gradient_arguments(double(bounding_box: nil))
      expect(arguments).to be nil
    end
  end

  describe "object bounding box with radial gradient" do
    let(:svg) do
      <<-SVG
        <radialGradient id="flag" cx="0" cy="0.2" fx="0.5" r="0.8">
          <stop offset="25%" stop-color="red"/>
          <stop offset="50%" stop-color="white"/>
          <stop offset="75%" stop-color="blue"/>
        </radialGradient>
      SVG
    end

    it "is stored in the document gradients table" do
      expect(document.gradients["flag"]).to eq element
    end

    it "returns correct gradient arguments for an element" do
      arguments = element.gradient_arguments(double(bounding_box: [100, 100, 200, 0]))
      expect(arguments).to eq(
        from: [150, 80],
        to:   [100, 80],
        r1:   0,
        r2:   Math.sqrt((0.8 * 100) ** 2 + (0.8 * 100) ** 2),
        stops: [[0, "ff0000"], [0.25, "ff0000"], [0.5, "ffffff"], [0.75, "0000ff"], [1, "0000ff"]],
        apply_transformations: true,
      )
    end
  end

  describe "user space on use with linear gradient" do
    let(:svg) do
      <<-SVG
        <linearGradient id="flag" gradientUnits="userSpaceOnUse" x1="100" y1="500" x2="200" y2="600">
          <stop offset="0" stop-color="red"/>
          <stop offset="1" stop-color="blue"/>
        </linearGradient>
      SVG
    end

    it "returns correct gradient arguments for an element" do
      arguments = element.gradient_arguments(double)
      expect(arguments).to eq(
        from: [100.0, 100.0],
        to:   [200.0, 0.0],
        stops: [[0, "ff0000"], [1, "0000ff"]],
        apply_transformations: true,
      )
    end
  end

  describe "user space on use with radial gradient" do
    let(:svg) do
      <<-SVG
        <radialGradient id="flag" gradientUnits="userSpaceOnUse" fx="100" fy="500" cx="200" cy="600" r="150">
          <stop offset="0" stop-color="red"/>
          <stop offset="1" stop-color="blue"/>
        </radialGradient>
      SVG
    end

    it "returns correct gradient arguments for an element" do
      arguments = element.gradient_arguments(double)
      expect(arguments).to eq(
        from: [100.0, 100.0],
        to:   [200.0, 0.0],
        r1:   0,
        r2:   150,
        stops: [[0, "ff0000"], [1, "0000ff"]],
        apply_transformations: true,
      )
    end
  end

  context "when gradientTransform is specified" do
    let(:svg) do
      <<-SVG
        <linearGradient id="flag" gradientTransform="translateX(10) scale(2)" x1="0" y1="0" x2="10" y2="10">
          <stop offset="0" stop-color="red"/>
          <stop offset="1" stop-color="blue"/>
        </linearGradient>
      SVG
    end

    it "passes in the transform via the apply_transformations option" do
      arguments = element.gradient_arguments(double(bounding_box: [0, 0, 10, 10]))

      expect(arguments).to eq(
        from: [0, 0],
        to:   [10, 10],
        stops: [[0, "ff0000"], [1, "0000ff"]],
        apply_transformations: [2, 0, 0, 2, 10, 0],
      )
    end
  end
end
