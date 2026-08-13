require 'spec_helper'

RSpec.describe Prawn::SVG::Elements::Marker do
  let(:svg) do
    <<-SVG
      <svg>
        <marker id="Triangle"
          viewBox="0 0 10 10" refX="0" refY="5"
          markerUnits="strokeWidth"
          markerWidth="4" markerHeight="3"
          orient="auto">
          <path d="M 0 0 L 10 5 L 0 10 z" />
        </marker>

        <line x2="10" y2="10" stroke="black" stroke-width="100" />
      </svg>
    SVG
  end

  let(:document) { Prawn::SVG::Document.new(svg, [800, 600], {width: 800, height: 600}) }
  let(:state) { Prawn::SVG::State.new }

  let(:line_element) do
    Prawn::SVG::Elements::Line.new(document, document.root.elements[2], [], state)
  end

  subject do
    Prawn::SVG::Elements::Marker.new(document, document.root.elements[1], [], state)
  end

  before do
    state.viewport_sizing = document.sizing
  end

  describe "#parse" do
    it "forces display none" do
      subject.parse
      expect(subject.properties.display).to eq 'none'
    end
  end

  describe "#apply_marker" do
    it "adds the line and its marker to the call stack" do
      subject.process
      line_element.process

      # We didn't use a marker-* attribute on the <line> tag, that's
      # why the apply_marker method wasn't automatically called as part
      # of the line_element.process call above.

      subject.apply_marker(line_element, point: [10, 10], angle: 45)

      # This example follows the example in the SVG 1.1 documentation
      # in section 11.6.3.

      expect(line_element.base_calls).to eq [
        ["stroke_color", ["000000"], {}, []],
        ["line_width", [100.0], {}, []],
        ["stroke", [], {}, [
            ["move_to", [[0.0, 600.0]], {}, []],
            ["line_to", [[10.0, 590.0]], {}, []]
          ]
        ],
        ["save", [], {}, []],
        ["transformation_matrix", [1, 0, 0, 1, 10, -10], {}, []],
        ["rotate", [-45], {origin: [0, 600.0]}, [
            ["transformation_matrix", [100.0, 0, 0, 100.0, 0, 0], {}, []],
            ["transformation_matrix", [1, 0, 0, 1, -0.0, 1.5], {}, []],
            ["rectangle", [[-0.5, 600.0], 4.0, 3.0], {}, []],
            ["clip", [], {}, []],
            ["transformation_matrix", [0.3, 0, 0, 0.3, 0, 0], {}, []],
            ["transparent", [1.0, 1.0], {}, [
                ["stroke_color", ["000000"], {}, []],
                ["line_width", [100.0], {}, []],
                ["cap_style", [:butt], {}, []],
                ["undash", [], {}, []],
                ["save", [], {}, []],
                ["fill", [], {}, [
                    ["join_style", [:bevel], {}, []],
                    ["move_to", [[0.0, 600.0]], {}, []],
                    ["line_to", [[10.0, 595.0]], {}, []],
                    ["line_to", [[0.0, 590.0]], {}, []],
                    ["close_path", [], {}, []]
                  ]
                ],
                ["restore", [], {}, []],
              ]
            ]
          ]
        ],
        ["restore", [], {}, []]
      ]
    end
  end
end
