require 'spec_helper'

describe "Integration test" do
  root = "#{File.dirname(__FILE__)}/.."

  describe "a basic SVG file" do
    let(:document) { Prawn::SVG::Document.new(svg, [800, 600], {}) }
    let(:element) { Prawn::SVG::Elements::Root.new(document) }

    let(:svg) do
      <<-SVG
<svg width="100" height="200">
  <style><![CDATA[
    #puppy  { fill: red; }
    .animal { fill: green; }
    rect    { fill: blue; }
  ]]></style>

  <rect x="0" y="0" width="10" height="10"/>
  <rect x="10" y="0" width="10" height="10" class="animal"/>
  <rect x="20" y="0" width="10" height="10" class="animal" id="puppy"/>
  <rect x="30" y="0" width="10" height="10" class="animal" id="puppy" style="fill: yellow;"/>
</svg>
      SVG
    end

    it "is correctly converted to a call stack" do
      element.process

      expect(element.calls).to eq [
        ["fill_color", ["000000"], {}, []],
        ["transformation_matrix", [1, 0, 0, 1, 0, 0], {}, []],
        ["transformation_matrix", [1, 0, 0, 1, 0, 0], {}, []],
        ["save", [], {}, []], ["restore", [], {}, []],
        ["save", [], {}, []],
        ["fill_color", ["0000ff"], {}, []],
        ["fill", [], {}, [
          ["rectangle", [[0.0, 200.0], 10.0, 10.0], {}, []]
        ]],
        ["restore", [], {}, []],
        ["save", [], {}, []],
        ["fill_color", ["008000"], {}, []],
        ["fill", [], {}, [
          ["rectangle", [[10.0, 200.0], 10.0, 10.0], {}, []]
        ]],
        ["restore", [], {}, []],
        ["save", [], {}, []],
        ["fill_color", ["ff0000"], {}, []],
        ["fill", [], {}, [
          ["rectangle", [[20.0, 200.0], 10.0, 10.0], {}, []]
        ]],
        ["restore", [], {}, []],
        ["save", [], {}, []],
        ["fill_color", ["ffff00"], {}, []],
        ["fill", [], {}, [
          ["rectangle", [[30.0, 200.0], 10.0, 10.0], {}, []]
        ]],
        ["restore", [], {}, []]
      ]
    end
  end

  context "with option :position" do
    let(:svg) { IO.read("#{root}/spec/sample_svg/cubic01a.svg") }

    it "aligns the image as requested" do
      Prawn::Document.generate("#{root}/spec/sample_output/_with_position.pdf") do |prawn|
        width = prawn.bounds.width / 3

        prawn.svg svg, :width => width, :position => :left
        prawn.svg svg, :width => width, :position => :center
        prawn.svg svg, :width => width, :position => :right
        prawn.svg svg, :width => width, :position => 50
        prawn.svg svg, :width => width
      end
    end
  end

  context "with option :vposition" do
    let(:svg) { IO.read("#{root}/spec/sample_svg/cubic01a.svg") }

    it "aligns the image as requested" do
      Prawn::Document.generate("#{root}/spec/sample_output/_with_vposition.pdf") do |prawn|
        width = prawn.bounds.width / 3

        prawn.svg svg, :width => width, :position => :left, :vposition => :bottom
        prawn.svg svg, :width => width, :position => :center, :vposition => :center
        prawn.svg svg, :width => width, :position => :right, :vposition => :top
        prawn.svg svg, :width => width, :position => 50, :vposition => 50
      end
    end
  end

  describe "sample file rendering" do
    files = Dir["#{root}/spec/sample_svg/*.svg"]

    it "has at least 10 SVG sample files to test" do
      files.length.should >= 10
    end

    files.each do |file|
      it "renders the #{File.basename file} sample file without warnings or crashing" do
        expect(Net::HTTP).to_not receive(:get)

        warnings = nil
        Prawn::Document.generate("#{root}/spec/sample_output/#{File.basename file}.pdf") do |prawn|
          r = prawn.svg IO.read(file), :at => [0, prawn.bounds.top], :width => prawn.bounds.width, :enable_file_requests_with_root => File.dirname(__FILE__) do |doc|
            doc.url_loader.add_to_cache("https://raw.githubusercontent.com/mogest/prawn-svg/master/spec/sample_images/mushroom-wide.jpg", IO.read("#{root}/spec/sample_images/mushroom-wide.jpg"))
            doc.url_loader.add_to_cache("https://raw.githubusercontent.com/mogest/prawn-svg/master/spec/sample_images/mushroom-long.jpg", IO.read("#{root}/spec/sample_images/mushroom-long.jpg"))
          end

          warnings = r[:warnings].reject {|w| w =~ /Verdana/ && w =~ /is not a known font/ || w =~ /(render gradients$|waiting on the Prawn project)/}
        end
        warnings.should == []
      end
    end
  end

  describe "multiple file rendering" do
    it "renders multiple files on to the same PDF" do
      Prawn::Document.generate("#{root}/spec/sample_output/_multiple.pdf") do |prawn|
        width = prawn.bounds.width

        y = prawn.bounds.top - 12
        prawn.draw_text "This is multiple SVGs being output to the same PDF", :at => [0, y]

        y -= 12
        prawn.svg IO.read("#{root}/spec/sample_svg/arcs01.svg"),   :at => [0, y],         :width => width / 2
        prawn.svg IO.read("#{root}/spec/sample_svg/circle01.svg"), :at => [width / 2, y], :width => width / 2

        y -= 120
        prawn.draw_text "Here are some more PDFs below", :at => [0, y]

        y -= 12
        prawn.svg IO.read("#{root}/spec/sample_svg/quad01.svg"), :at => [0, y],             :width => width / 3
        prawn.svg IO.read("#{root}/spec/sample_svg/rect01.svg"), :at => [width / 3, y],     :width => width / 3
        prawn.svg IO.read("#{root}/spec/sample_svg/rect02.svg"), :at => [width / 3 * 2, y], :width => width / 3
      end
    end
  end
end
