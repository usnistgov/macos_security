require 'spec_helper'

RSpec.describe Prawn::SVG::Pathable do
  class FakeElement < Prawn::SVG::Elements::Base
    include Prawn::SVG::Pathable

    def initialize(*args)
      super
      @properties = Struct.new(:marker_start, :marker_mid, :marker_end).new
    end

    public :apply_commands
    public :apply_markers

    def commands
      @commands ||= [
        Prawn::SVG::Pathable::Move.new([10, 10]),
        Prawn::SVG::Pathable::Line.new([20, 20]),
        Prawn::SVG::Pathable::Curve.new([30, 30], [25, 20], [25, 25]),
        Prawn::SVG::Pathable::Close.new([10, 10])
      ]
    end
  end

  let(:document) { Prawn::SVG::Document.new("<svg></svg>", [800, 600], {width: 800, height: 600}) }
  let(:state) { Prawn::SVG::State.new }

  subject do
    FakeElement.new(document, document.root, [], state)
  end

  describe "#bounding_box" do
    it "determines the bounding box using the translated commands" do
      expect(subject.bounding_box).to eq [10, 590, 30, 570]
    end
  end

  describe "#apply_commands" do
    it "applies the commands to the call stack" do
      subject.apply_commands

      expect(subject.base_calls).to eq [
        ["move_to", [[10.0, 590.0]], {}, []],
        ["line_to", [[20.0, 580.0]], {}, []],
        ["curve_to", [[30.0, 570.0]], {bounds: [[25.0, 580.0], [25.0, 575.0]]}, []],
        ["close_path", [], {}, []]
      ]
    end
  end

  describe "#apply_markers" do
    let(:marker) { instance_double(Prawn::SVG::Elements::Marker, name: "marker") }

    before do
      document.elements_by_id["triangle"] = marker
    end

    context "with marker-start attribute specified" do
      before do
        subject.properties.marker_start = "url(#triangle)"
      end

      it "calls apply_marker on the marker" do
        expect(marker).to receive(:apply_marker).with(subject, point: [10, 10], angle: 45)
        subject.apply_markers
      end
    end

    context "with marker-mid attribute specified" do
      before do
        subject.properties.marker_mid = "url(#triangle)"
      end

      it "calls apply_marker on the marker" do
        expect(marker).to receive(:apply_marker).with(subject, point: [20, 20], angle: 45)
        expect(marker).to receive(:apply_marker).with(subject, point: [30, 30], angle: -45)
        subject.apply_markers
      end
    end

    context "with marker-end attribute specified" do
      before do
        subject.properties.marker_end = "url(#triangle)"
      end

      it "calls apply_marker on the marker" do
        expect(marker).to receive(:apply_marker).with(subject, point: [10, 10], angle: -45)
        subject.apply_markers
      end
    end
  end
end
