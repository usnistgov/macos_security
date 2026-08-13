require File.dirname(__FILE__) + '/../../../spec_helper'

describe Prawn::SVG::Elements::Text do
  let(:document) { Prawn::SVG::Document.new(svg, [800, 600], {}, font_registry: Prawn::SVG::FontRegistry.new("Helvetica" => {:normal => nil}, "Courier" => {normal: nil}, 'Times-Roman' => {normal: nil})) }
  let(:element)  { Prawn::SVG::Elements::Text.new(document, document.root, [], fake_state) }

  let(:default_style) { {:size=>16, :style=>:normal, :text_anchor=>'start', :at=>[:relative, :relative], :offset=>[0,0]} }

  describe "xml:space preserve" do
    let(:svg) { %(<text#{attributes}>some\n\t  text</text>) }

    context "when xml:space is preserve" do
      let(:attributes) { ' xml:space="preserve"' }

      it "converts newlines and tabs to spaces, and preserves spaces" do
        element.process

        expect(flatten_calls(element.calls)).to include ["draw_text", ["some    text"], {:size=>16, :style=>:normal, :text_anchor=>'start', :at=>[:relative, :relative], :offset=>[0,0]}]
      end
    end

    context "when xml:space is unspecified" do
      let(:attributes) { '' }

      it "strips space" do
        element.process

        expect(flatten_calls(element.calls)).to include ["draw_text", ["some text"], {:size=>16, :style=>:normal, :text_anchor=>'start', :at=>[:relative, :relative], :offset=>[0,0]}]
      end
    end
  end

  describe "conventional whitespace handling" do
    let(:svg) do
      <<-SVG
<text>
  <tspan>
  </tspan>
  Some text here
  <tspan>More text</tspan>
Even more
<tspan></tspan>
<tspan>
  leading goodness
  </tspan>
  ok
      <tspan>
      </tspan>
</text>
      SVG
    end

    it "correctly apportions white space between the tags" do
      element.process
      calls = element.calls.flatten
      expect(calls).to include "Some text here "
      expect(calls).to include "More text"
      expect(calls).to include "Even more"
      expect(calls).to include " leading goodness "
      expect(calls).to include "ok"
    end
  end

  describe "when text-anchor is specified" do
    let(:svg) { '<g text-anchor="middle" font-size="12"><text x="50" y="14">Text</text></g>' }
    let(:element) { Prawn::SVG::Elements::Container.new(document, document.root, [], fake_state) }

    it "should inherit text-anchor from parent element" do
      element.process
      expect(element.calls.flatten).to include(:size => 12.0, :style => :normal, :text_anchor => "middle", :at => [50.0, 586.0], :offset => [0,0])
    end
  end

  describe "letter-spacing" do
    let(:svg) { '<text letter-spacing="5">spaced</text>' }

    it "calls character_spacing with the requested size" do
      element.process

      expect(element.base_calls).to eq [
        ["text_group", [], {}, [
          ["font", ["Helvetica"], {style: :normal}, []],
          ["character_spacing", [5.0], {}, [
            ["draw_text", ["spaced"], default_style, []]
          ]]
        ]]
      ]
    end
  end

  describe "underline" do
    let(:svg) { '<text text-decoration="underline">underlined</text>' }

    it "marks the element to be underlined" do
      element.process

      expect(element.base_calls).to eq [
        ["text_group", [], {},[
          ["font", ["Helvetica"], {:style=>:normal}, []],
          ["draw_text", ["underlined"], default_style.merge(decoration: 'underline'), []]
        ]]
      ]
    end
  end

  describe "fill/stroke modes" do
    context "with a stroke and no fill" do
      let(:svg) { '<text stroke="red" fill="none">stroked</text>' }

      it "calls text_rendering_mode with the requested options" do
        element.process

        expect(element.base_calls).to eq [
          ["text_group", [], {}, [
            ["stroke_color", ["ff0000"], {}, []],
            ["font", ["Helvetica"], {style: :normal}, []],
            ["text_rendering_mode", [:stroke], {}, [
              ["draw_text", ["stroked"], default_style, []]
            ]]
          ]]
        ]
      end
    end

    context "with a mixture of everything" do
      let(:svg) { '<text stroke="red" fill="none">stroked <tspan fill="black">both</tspan><tspan stroke="none">neither</tspan></text>' }

      it "calls text_rendering_mode with the requested options" do
        element.process

        expect(element.base_calls).to eq [
          ["text_group", [], {}, [
            ["stroke_color", ["ff0000"], {}, []],
            ["font", ["Helvetica"], {style: :normal}, []],
            ["text_rendering_mode", [:stroke], {}, [
              ["draw_text", ["stroked "], default_style, []],
              ["save", [], {}, []],
              ["fill_color", ["000000"], {}, []],
              ["font", ["Helvetica"], {style: :normal}, []],
              ["text_rendering_mode", [:fill_stroke], {}, [
                ["draw_text", ["both"], default_style, []]
              ]],
              ["restore", [], {}, []],
              ["save", [], {}, []],
              ["font", ["Helvetica"], {style: :normal}, []],
              ["text_rendering_mode", [:invisible], {}, [
                ["draw_text", ["neither"], default_style, []]
              ]],
              ["restore", [], {}, []],
            ]]
          ]]
        ]
      end
    end
  end

  describe "font finding" do
    context "with a font that exists" do
      let(:svg) { '<text font-family="monospace">hello</text>' }

      it "finds the font and uses it" do
        element.process
        expect(flatten_calls(element.base_calls)).to include ['font', ['Courier'], {style: :normal}]
      end
    end

    context "with a font that doesn't exist" do
      let(:svg) { '<text font-family="does not exist">hello</text>' }

      it "uses the fallback font" do
        element.process
        expect(flatten_calls(element.base_calls)).to include ['font', ['Times-Roman'], {style: :normal}]
      end

      context "when there is no fallback font" do
        before { document.font_registry.installed_fonts.delete("Times-Roman") }

        it "doesn't call the font method and logs a warning" do
          element.process
          expect(element.base_calls.flatten).to_not include 'font'
          expect(document.warnings.first).to include "is not a known font"
        end
      end
    end
  end

  describe "<tref>" do
    let(:svg) { '<svg xmlns:xlink="http://www.w3.org/1999/xlink"><defs><text id="ref" fill="green">my reference text</text></defs><text x="10"><tref xlink:href="#ref" fill="red" /></text></svg>' }
    let(:element) { Prawn::SVG::Elements::Root.new(document, document.root, [], fake_state) }

    it "references the text" do
      element.process
      expect(flatten_calls(element.base_calls)[9..11]).to eq [
        ["fill_color", ["ff0000"], {}],
        ["font", ["Helvetica"], {:style=>:normal}],
        ["draw_text", ["my reference text"], {:size=>16, :style=>:normal, :text_anchor=>"start", :at=>[10.0, :relative], :offset=>[0,0]}],
      ]
    end
  end

  describe "dx and dy attributes" do
    let(:svg) { '<text x="10 20" dx="30 50 80" dy="2">Hi there, this is a good test</text>' }

    it "correctly calculates the positions of the text" do
      element.process

      expect(flatten_calls(element.base_calls)).to eq [
        ["text_group", [], {}],
        ["font", ["Helvetica"], {:style=>:normal}],
        ["draw_text", ["H"], {:size=>16, :style=>:normal, :text_anchor=>"start", :at=>[10.0, :relative], :offset=>[30.0, 2.0]}],
        ["draw_text", ["i"], {:size=>16, :style=>:normal, :text_anchor=>"start", :at=>[20.0, :relative], :offset=>[50.0, 0]}],
        ["draw_text", [" there, this is a good test"], {:size=>16, :style=>:normal, :text_anchor=>"start", :at=>[:relative, :relative], :offset=>[80.0, 0]}]
      ]
    end
  end

  describe "rotate attribute" do
    let(:svg) { '<text rotate="10 20 30 40 50 60 70 80 90 100">Hi <tspan rotate="0">this</tspan> ok!</text>' }

    it "correctly calculates the positions of the text" do
      element.process

      expect(flatten_calls(element.base_calls)).to eq [
        ["text_group", [], {}],
        ["font", ["Helvetica"], {:style=>:normal}],
        ["draw_text", ["H"], {:size=>16, :style=>:normal, :text_anchor=>"start", :at=>[:relative, :relative], :offset=>[0, 0], :rotate=>-10.0}],
        ["draw_text", ["i"], {:size=>16, :style=>:normal, :text_anchor=>"start", :at=>[:relative, :relative], :offset=>[0, 0], :rotate=>-20.0}],
        ["draw_text", [" "], {:size=>16, :style=>:normal, :text_anchor=>"start", :at=>[:relative, :relative], :offset=>[0, 0], :rotate=>-30.0}],
        ["save", [], {}],
        ["font", ["Helvetica"], {:style=>:normal}],
        ["draw_text", ["this"], {:size=>16, :style=>:normal, :text_anchor=>"start", :at=>[:relative, :relative], :offset=>[0, 0]}],
        ["restore", [], {}],
        ["draw_text", [" "], {:size=>16, :style=>:normal, :text_anchor=>"start", :at=>[:relative, :relative], :offset=>[0, 0], :rotate=>-80.0}],
        ["draw_text", ["o"], {:size=>16, :style=>:normal, :text_anchor=>"start", :at=>[:relative, :relative], :offset=>[0, 0], :rotate=>-90.0}],
        ["draw_text", ["k"], {:size=>16, :style=>:normal, :text_anchor=>"start", :at=>[:relative, :relative], :offset=>[0, 0], :rotate=>-100.0}],
        ["draw_text", ["!"], {:size=>16, :style=>:normal, :text_anchor=>"start", :at=>[:relative, :relative], :offset=>[0, 0], :rotate=>-100.0}]
      ]
    end
  end
end
