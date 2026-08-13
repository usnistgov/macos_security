require 'spec_helper'

describe Prawn::SVG::Elements::Base do
  let(:svg) { "<svg></svg>" }
  let(:document) { Prawn::SVG::Document.new(svg, [800, 600], {}, font_registry: Prawn::SVG::FontRegistry.new("Helvetica" => {:normal => nil})) }
  let(:parent_calls) { [] }
  let(:element) { Prawn::SVG::Elements::Base.new(document, document.root, parent_calls, fake_state) }

  describe "#initialize" do
    let(:svg) { '<something id="hello"/>' }

    it "adds itself to the elements_by_id hash if an id attribute is supplied" do
      element
      expect(document.elements_by_id["hello"]).to eq element
    end
  end

  describe "#process" do
    it "calls #parse and #apply so subclasses can parse the element" do
      expect(element).to receive(:parse).ordered
      expect(element).to receive(:apply).ordered
      element.process
    end

    describe "applying calls from the standard attributes" do
      let(:svg) do
        <<-SVG
          <something transform="scale(2)" fill-opacity="0.5" fill="red" stroke="blue" stroke-width="5"/>
        SVG
      end

      it "appends the relevant calls" do
        element.process
        expect(element.base_calls).to eq [
          ["transformation_matrix", [2, 0, 0, 2, 0, 0], {}, [
            ["transparent", [0.5, 1], {}, [
              ["fill_color", ["ff0000"], {}, []],
              ["stroke_color", ["0000ff"], {}, []],
              ["line_width", [5.0], {}, []],
              ["fill_and_stroke", [], {}, []]
            ]]
          ]]
        ]
      end
    end

    describe "fills and strokes" do
      before { element.process }
      subject { element.base_calls.last }

      context "with neither fill nor stroke" do
        let(:svg) { '<rect style="fill: none;"></rect>' }
        it        { is_expected.to eq ['end_path', [], {}, []] }
      end

      context "with a fill only" do
        let(:svg) { '<rect style="fill: black;"></rect>' }
        it        { is_expected.to eq ['fill', [], {}, []] }
      end

      context "with a stroke only" do
        let(:svg) { '<rect style="fill: none; stroke: black;"></rect>' }
        it        { is_expected.to eq ['stroke', [], {}, []] }
      end

      context "with fill and stroke" do
        let(:svg) { '<rect style="fill: black; stroke: black;"></rect>' }
        it        { is_expected.to eq ['fill_and_stroke', [], {}, []] }
      end

      context "with fill with evenodd fill rule" do
        let(:svg) { '<rect style="fill: black; fill-rule: evenodd;"></rect>' }
        it        { is_expected.to eq ['fill', [], {fill_rule: :even_odd}, []] }
      end
    end

    it "appends calls to the parent element" do
      expect(element).to receive(:apply) do
        element.send :add_call, "test", "argument", kw: 'argument'
      end

      element.process
      expect(element.parent_calls).to eq [["fill", [], {}, [["test", ["argument"], {kw: 'argument'}, []]]]]
    end

    it "quietly absorbs a SkipElementQuietly exception" do
      expect(element).to receive(:parse).and_raise(Prawn::SVG::Elements::Base::SkipElementQuietly)
      expect(element).to_not receive(:apply)
      element.process
      expect(document.warnings).to be_empty
    end

    it "absorbs a SkipElementError exception, logging a warning" do
      expect(element).to receive(:parse).and_raise(Prawn::SVG::Elements::Base::SkipElementError, "hello")
      expect(element).to_not receive(:apply)
      element.process
      expect(document.warnings).to eq ["hello"]
    end
  end

  describe "#apply_colors" do
    before do
      element.send(:extract_attributes_and_properties)
    end

    subject { element.send :apply_colors }

    it "doesn't change anything if no fill attribute provided" do
      expect(element).to_not receive(:add_call)
      subject
    end

    it "doesn't change anything if 'inherit' fill attribute provided" do
      element.properties.fill = 'inherit'
      expect(element).to_not receive(:add_call)
      subject
    end

    it "doesn't change anything if 'none' fill attribute provided" do
      element.properties.fill = 'none'
      expect(element).to_not receive(:add_call)
      subject
    end

    it "uses the fill attribute's color" do
      expect(element).to receive(:add_call).with('fill_color', 'ff0000')
      element.properties.fill = 'red'
      subject
    end

    it "uses black if the fill attribute's color is unparseable" do
      expect(element).to receive(:add_call).with('fill_color', '000000')
      element.properties.fill = 'blarble'
      subject
    end

    it "uses the color attribute if 'currentColor' fill attribute provided" do
      expect(element).to receive(:add_call).with('fill_color', 'ff0000')
      element.properties.fill = 'currentColor'
      element.state.computed_properties.color = 'red'
      subject
    end

    context "with a color attribute defined on a parent element" do
      let(:svg) { '<svg style="color: green;"><g style="color: red;"><rect width="10" height="10" style="fill: currentColor;"></rect></g></svg>' }
      let(:element) { Prawn::SVG::Elements::Root.new(document, document.root, parent_calls) }
      let(:flattened_calls) { flatten_calls(element.base_calls) }

      it "uses the parent's color element if 'currentColor' fill attribute provided" do
        element.process

        expect(flattened_calls).to include ['fill_color', ['ff0000'], {}]
        expect(flattened_calls).not_to include ['fill_color', ['00ff00'], {}]
      end
    end

    it "computes to 'none' if UnresolvableURLWithNoFallbackError is raised" do
      expect(element).to_not receive(:add_call)
      element.properties.fill = 'url()'
      subject
      expect(element.computed_properties.fill).to eq 'none'
    end
  end

  describe "stylesheets" do
    let(:svg) { <<-SVG }
      <svg>
        <style>
          .special rect { fill: green; }
          rect { fill: red; }
        </style>
        <rect width="100" height="100"></rect>
        <g class="special">
          <rect width="100" height="100"></rect>
          <rect width="100" height="100" style="fill: yellow;"></rect>
        </g>
      </svg>
    SVG

    it "applies stylesheet styling but style attributes take precedence" do
      document = Prawn::SVG::Document.new(svg, [100, 100], {})
      calls = []
      element = Prawn::SVG::Elements::Root.new(document, document.root, calls)
      element.process

      fill_colors = calls.select { |cmd, _, _| cmd == 'fill_color' }.map { |_, args, _| args.first }
      expect(fill_colors).to eq ['000000', 'ff0000', '008000', 'ffff00']
    end
  end
end
