require 'spec_helper'

RSpec.describe Prawn::SVG::CSS::Stylesheets do
  describe "typical usage" do
    let(:svg) { <<-SVG }
      <svg>
        <style>
          #inner rect { fill: #0000ff; }
          #outer { fill: #220000; }
          .hero > rect { fill: #00ff00; }
          rect { fill: #ff0000; }
          rect ~ rect { fill: #330000; }
          rect + rect { fill: #440000; }
          rect:first-child:last-child { fill: #441234; }

          circle:first-child { fill: #550000; }
          circle:nth-child(2) { fill: #660000; }
          circle:last-child { fill: #770000; }

          square[chocolate] { fill: #880000; }
          square[abc=def] { fill: #990000; }
          square[abc^=ghi] { fill: #aa0000; }
          square[abc$=jkl] { fill: #bb0000; }
          square[abc*=mno] { fill: #cc0000; }
          square[abc~=pqr] { fill: #dd0000; }
          square[abc|=stu] { fill: #ee0000; }
        </style>

        <rect width="1" height="1" />
        <rect width="2" height="2" id="outer" />

        <g class="hero large">
          <rect width="3" height="3" />
          <rect width="4" height="4" style="fill: #777777;" />
          <rect width="5" height="5" />

          <g id="inner">
            <rect width="6" height="6" />
          </g>

          <circle width="100" />

          <g id="circles">
            <circle width="7" />
            <circle width="8" />
            <circle width="9" />
          </g>
        </g>

        <square width="10" chocolate="hi there" />
        <square width="11" abc="def" />
        <square width="12" abc="ghidef" />
        <square width="13" abc="aghidefjkl" />
        <square width="14" abc="agmnohidefjklx" />
        <square width="15" abc="aeo cnj pqr" />
        <square width="16" abc="eij-stu-asd" />
      </svg>
    SVG

    it "associates styles with elements" do
      result = Prawn::SVG::CSS::Stylesheets.new(CssParser::Parser.new, REXML::Document.new(svg)).load
      width_and_styles = result.map { |k, v| [k.attributes["width"].to_i, v] }.sort_by(&:first)

      expected = [
        [1, [["fill", "#ff0000", false]]],
        [2, [["fill", "#ff0000", false], ["fill", "#330000", false], ["fill", "#440000", false], ["fill", "#220000", false]]],
        [3, [["fill", "#ff0000", false], ["fill", "#00ff00", false]]],
        [4, [["fill", "#ff0000", false], ["fill", "#330000", false], ["fill", "#440000", false], ["fill", "#00ff00", false]]],
      ]

      expected << [5, [["fill", "#ff0000", false], ["fill", "#330000", false], ["fill", "#330000", false], ["fill", "#440000", false], ["fill", "#00ff00", false]]]

      expected.concat [
        [6, [["fill", "#ff0000", false], ["fill", "#441234", false], ["fill", "#0000ff", false]]],
        [7, [["fill", "#550000", false]]],
        [8, [["fill", "#660000", false]]],
        [9, [["fill", "#770000", false]]],
        [10, [["fill", "#880000", false]]],
        [11, [["fill", "#990000", false]]],
        [12, [["fill", "#aa0000", false]]],
        [13, [["fill", "#bb0000", false]]],
        [14, [["fill", "#cc0000", false]]],
        [15, [["fill", "#dd0000", false]]],
        [16, [["fill", "#ee0000", false]]],
      ]

      expect(width_and_styles).to eq(expected)
    end
  end

  describe "style tag parsing" do
    let(:svg) do
      <<-SVG
<svg>
  <some-tag>
    <style>a
  before&gt;
  x <![CDATA[ y
  inside <>&gt;
  k ]]> j
  after
z</style>
  </some-tag>

  <other-tag>
    <more-tag>
      <style>hello</style>
    </more-tag>
  </other-tag>
</svg>
      SVG
    end

    it "scans the document for style tags and adds the style information to the css parser" do
      css_parser = instance_double(CssParser::Parser)

      expect(css_parser).to receive(:add_block!).with("a\n  before>\n  x  y\n  inside <>&gt;\n  k  j\n  after\nz")
      expect(css_parser).to receive(:add_block!).with("hello")
      allow(css_parser).to receive(:each_rule_set)

      Prawn::SVG::CSS::Stylesheets.new(css_parser, REXML::Document.new(svg)).load
    end
  end
end
