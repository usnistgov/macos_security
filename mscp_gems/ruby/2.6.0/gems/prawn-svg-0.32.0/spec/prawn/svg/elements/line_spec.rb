require 'spec_helper'

RSpec.describe Prawn::SVG::Elements::Line do
  let(:document) { Prawn::SVG::Document.new(svg, [800, 600], {width: 800, height: 600}) }

  subject do
    Prawn::SVG::Elements::Line.new(document, document.root, [], fake_state)
  end

  context "with attributes specified" do
    let(:svg) { '<line x1="5" y1="10" x2="15" y2="20" stroke="black" />' }

    it "renders the line" do
      subject.process
      expect(subject.base_calls).to eq [
        ["stroke_color", ["000000"], {}, []],
        ["stroke", [], {}, [
          ["move_to", [[5.0, 590.0]], {}, []],
          ["line_to", [[15.0, 580.0]], {}, []]]
        ]
      ]
    end
  end

  context "with no attributes nor stroke specified" do
    let(:svg) { '<line />' }

    it "outlines a path from 0,0 to 0,0" do
      subject.process
      expect(subject.base_calls).to eq [
        ["end_path", [], {}, [
          ["move_to", [[0, 600]], {}, []],
          ["line_to", [[0, 600]], {}, []]]
        ]
      ]
    end
  end

  context "with a fill specified" do
    let(:svg) { '<line x1="0" y1="0" x2="15" y2="20" style="stroke: red; fill: blue;" />' }

    it "ignores the fill" do
      subject.process

      expect(subject.base_calls).to eq [
        ["fill_color", ["0000ff"], {}, []],
        ["stroke_color", ["ff0000"], {}, []],
        ["stroke", [], {}, [
          ["move_to", [[0, 600]], {}, []],
          ["line_to", [[15.0, 580.0]], {}, []]]
        ]
      ]
    end
  end
end
