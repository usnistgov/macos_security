require 'spec_helper'

RSpec.describe Prawn::SVG::Elements::Polyline do
  let(:document) { Prawn::SVG::Document.new(svg, [800, 600], {width: 800, height: 600}) }

  subject do
    Prawn::SVG::Elements::Polyline.new(document, document.root, [], Prawn::SVG::State.new)
  end

  context "with a valid points attribute" do
    let(:svg) { '<polyline points="10 10 20,20 30,30" />' }

    it "renders the polyline" do
      subject.process
      expect(subject.base_calls).to eq [
        ["fill", [], {}, [
          ["move_to", [[10.0, 590.0]], {}, []],
          ["line_to", [[20.0, 580.0]], {}, []],
          ["line_to", [[30.0, 570.0]], {}, []]]
        ]
      ]
    end
  end

  context "with a polyline that has an odd number of arguments" do
    let(:svg) { '<polyline points="10 10 20,20 30" />' }

    it "ignores the last one" do
      subject.process
      expect(subject.base_calls).to eq [
        ["fill", [], {}, [
          ["move_to", [[10.0, 590.0]], {}, []],
          ["line_to", [[20.0, 580.0]], {}, []]]
        ]
      ]
    end
  end

  context "with a polyline that has no arguments" do
    let(:svg) { '<polyline points="" />' }

    it "renders nothing" do
      subject.process
      expect(subject.base_calls).to eq []
    end
  end
end
