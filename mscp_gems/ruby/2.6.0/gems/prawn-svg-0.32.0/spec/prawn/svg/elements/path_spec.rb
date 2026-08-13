require 'spec_helper'

describe Prawn::SVG::Elements::Path do
  let(:source) { double(name: "path", attributes: {}) }
  let(:state) { Prawn::SVG::State.new }
  let(:path) { Prawn::SVG::Elements::Path.new(nil, source, [], state) }

  before do
    allow(path).to receive(:attributes).and_return("d" => d)
  end

  describe "command parsing" do
    context "with a valid path" do
      let(:d) { "m12.34 -56.78 1 2M4 5 12-34 -.5.7+3 2.3e3 4e4 4e+4 L31,-2e-5L  6,7 Z ZZa50 50 0 100 100" }

      it "correctly parses" do
        calls = []
        allow(path).to receive(:parse_path_command) {|*args| calls << args}
        path.parse

        expect(calls).to eq [
          ["m", [[12.34, -56.78], [1, 2]]],
          ["M", [[4, 5], [12, -34], [-0.5, 0.7], [3, 2.3e3], [4e4, 4e4]]],
          ["L", [[31, -2e-5]]],
          ["L", [[6, 7]]],
          ["Z", []],
          ["Z", []],
          ["Z", []],
          ["a", [[50, 50, 0, 1, 0, 0, 100]]],
        ]
      end
    end

    context "with m and M commands" do
      let(:d) { "M 1,2 3,4 m 5,6 7,8" }

      it "treats subsequent points to m/M command as relative/absolute depending on command" do
        [
          ["M", [[1,2],[3,4]]],
          ["L", [[3,4]]],
          ["m", [[5,6],[7,8]]],
          ["l", [[7,8]]]
        ].each do |args|
          expect(path).to receive(:parse_path_command).with(*args).and_call_original
        end

        path.parse
      end
    end

    context "with an empty path" do
      let(:d) { "" }

      it "correctly parses" do
        expect(path).not_to receive(:run_path_command)
        path.parse
      end
    end

    context "with a path with invalid characters" do
      let(:d) { "M 10 % 20" }

      it "raises" do
        expect { path.parse }.to raise_error(Prawn::SVG::Elements::Base::SkipElementError)
      end
    end

    context "with a path with numerical data before a command letter" do
      let(:d) { "M 10 % 20" }

      it "raises" do
        expect { path.parse }.to raise_error(Prawn::SVG::Elements::Base::SkipElementError)
      end
    end
  end

  context "when given an M path" do
    subject { path.parse; path.commands }

    context "with typical arguments" do
      let(:d) { "M 100 200 M 200 300 m 10 20" }

      it "issues a move command" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 200.0]),
          Prawn::SVG::Elements::Path::Move.new([200.0, 300.0]),
          Prawn::SVG::Elements::Path::Move.new([210.0, 320.0]),
        ]
      end
    end

    context "with only one argument" do
      let(:d) { "M 100 200 M 100" }

      it "bails out" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 200.0])
        ]
      end
    end

    context "with no arguments" do
      let(:d) { "M 100 200 M" }

      it "bails out" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 200.0])
        ]
      end
    end
  end

  context "when given an L path" do
    subject { path.parse; path.commands }

    context "with typical arguments" do
      let(:d) { "M 100 200 L 200 300 l 10 20" }

      it "issues a line command" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 200.0]),
          Prawn::SVG::Elements::Path::Line.new([200.0, 300.0]),
          Prawn::SVG::Elements::Path::Line.new([210.0, 320.0]),
        ]
      end
    end

    context "with only one argument" do
      let(:d) { "M 100 200 L 100" }

      it "bails out" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 200.0])
        ]
      end
    end
  end

  context "when given a C path" do
    subject { path.parse; path.commands }

    context "with typical arguments" do
      let(:d) { "M 100 200 C 10 20 30 40 200 300" }

      it "issues a curve command" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 200.0]),
          Prawn::SVG::Elements::Path::Curve.new([200.0, 300.0], [10, 20], [30, 40]),
        ]
      end
    end

    context "with incomplete arguments" do
      let(:d) { "M 100 200 C 10 20 30 40 50" }

      it "bails out" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 200.0])
        ]
      end
    end
  end

  context "when given an S path" do
    subject { path.parse; path.commands }

    context "with typical arguments" do
      let(:d) { "M 100 200 S 30 40 200 300" }

      it "issues a curve command" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 200.0]),
          Prawn::SVG::Elements::Path::Curve.new([200.0, 300.0], [100, 200], [30, 40]),
        ]
      end
    end

    context "with incomplete arguments" do
      let(:d) { "M 100 200 S 30 40 50" }

      it "bails out" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 200.0])
        ]
      end
    end
  end

  context "when given a Q path" do
    subject { path.parse; path.commands }

    context "with typical arguments" do
      let(:d) { "M 0 0 Q 600 300 300 600" }

      it "issues a curve command" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([0, 0]),
          Prawn::SVG::Elements::Path::Curve.new([300.0, 600.0], [400, 200], [500, 400])
        ]
      end
    end

    context "with incomplete arguments" do
      let(:d) { "M 100 200 Q 30 40 50" }

      it "bails out" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 200.0])
        ]
      end
    end
  end

  context "when given a T path" do
    subject { path.parse; path.commands }

    context "with typical arguments" do
      let(:d) { "M 0 0 T 300 600" }

      it "issues a curve command" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([0, 0]),
          Prawn::SVG::Elements::Path::Curve.new([300.0, 600.0], [0, 0], [100, 200])
        ]
      end
    end

    context "with incomplete arguments" do
      let(:d) { "M 100 200 T 30" }

      it "bails out" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 200.0])
        ]
      end
    end
  end

  context "when given an A path" do
    subject { path.parse; path.commands }

    context "that is pretty normal" do
      let(:d) { "M 100 200 A 10 10 0 0 1 200 200" }

      it "uses bezier curves to approximate an arc path" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 200.0]),
          Prawn::SVG::Elements::Path::Curve.new([150.0, 150.0], [100.0, 172.57081148225683], [122.57081148225683, 150.0]),
          Prawn::SVG::Elements::Path::Curve.new([200.0, 200.0], [177.42918851774317, 150.0], [200.0, 172.57081148225683])
        ]
      end
    end

    context "with an identical start and end point" do
      let(:d) { "M 100 200 A 30 30 0 0 1 100 200" }

      it "ignores the path" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 200.0]),
        ]
      end
    end

    context "with an rx of 0" do
      let(:d) { "M 100 200 A 0 10 0 0 1 200 200" }

      it "substitutes a line_to" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 200.0]),
          Prawn::SVG::Elements::Path::Line.new([200.0, 200.0])
        ]
      end
    end

    context "with an ry of 0" do
      let(:d) { "M 100 200 A 10 0 0 0 1 200 200" }

      it "substitutes a line_to" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 200.0]),
          Prawn::SVG::Elements::Path::Line.new([200.0, 200.0])
        ]
      end
    end

    context "with incomplete arguments" do
      let(:d) { "M 100 200 A 10 20 30 L 10 20" }

      it "bails out" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 200.0])
        ]
      end
    end

    context "with highly-compressed flags" do
      let(:d) { "M100,100a50 50 0 100 100" }

      it "correctly parses them" do
        expect(subject).to eq [
          Prawn::SVG::Elements::Path::Move.new([100.0, 100.0]),
          Prawn::SVG::Elements::Path::Curve.new([50.0, 150.0], [72.57081148225681, 100.0], [50.0, 122.57081148225681]),
          Prawn::SVG::Elements::Path::Curve.new([99.99999999999999, 200.0], [50.0, 177.42918851774317], [72.5708114822568, 200.0])
        ]
      end
    end
  end
end
