require 'spec_helper'

describe Prawn::SVG::Interface do
  let(:bounds) { double(width: 800, height: 600, absolute_left: 0, absolute_top: 0) }
  let(:prawn)  { instance_double(Prawn::Document, font_families: {}, bounds: bounds, cursor: 600) }
  let(:svg)    { '<svg width="250" height="100"></svg>' }

  describe "#initialize" do
    describe "invalid option detection" do
      it "rejects invalid options when debug is on" do
        allow(Prawn).to receive(:debug).and_return(true)

        expect {
          Prawn::SVG::Interface.new(svg, prawn, :invalid => "option")
        }.to raise_error(Prawn::Errors::UnknownOption)
      end

      it "does nothing if an invalid option is given and debug is off" do
        Prawn::SVG::Interface.new(svg, prawn, :invalid => "option")
      end
    end
  end

  describe "#draw" do
    context "when the sizing object indicates the sizes are invalid" do
      let(:interface) { Prawn::SVG::Interface.new('<svg width="0"></svg>', prawn, {}) }

      it "doesn't draw anything and adds a warning" do
        interface.draw
        expect(interface.document.warnings).to eq ["Zero or negative sizing data means this SVG cannot be rendered"]
      end
    end

    describe "rewrites" do
      before do
        [:save_font, :bounding_box].each { |message| allow(prawn).to receive(message).and_yield }
        allow(prawn).to receive_messages([:move_to, :line_to, :close_path, :fill_color, :stroke_color, :transformation_matrix, :restore_graphics_state])
        allow(prawn).to receive(:save_graphics_state) { |&block| block.call if block }
      end

      context "when fill_and_stroke is issued" do
        context "and fill rule is not set" do
          let(:interface) { Prawn::SVG::Interface.new('<svg width="250" height="100"><rect width="10" height="10" stroke="red"></rect></svg>', prawn, {}) }

          it "adds content 'B'" do
            expect(prawn).to receive(:rectangle).with([0, 100], 10, 10)
            expect(prawn).to receive(:add_content).with("W n")
            expect(prawn).to receive(:add_content).with("B")
            interface.draw
          end
        end

        context "and fill rule is evenodd" do
          let(:interface) { Prawn::SVG::Interface.new('<svg width="250" height="100"><rect width="10" height="10" stroke="red" fill-rule="evenodd"></rect></svg>', prawn, {}) }

          it "adds content 'B*'" do
            expect(prawn).to receive(:rectangle).with([0, 100], 10, 10)
            expect(prawn).to receive(:add_content).with("W n")
            expect(prawn).to receive(:add_content).with("B*")
            interface.draw
          end
        end
      end
    end
  end

  describe "#position" do
    subject { interface.position }

    context "when options[:at] supplied" do
      let(:interface) { Prawn::SVG::Interface.new(svg, prawn, at: [1, 2], position: :left) }

      it "returns options[:at]" do
        expect(subject).to eq [1, 2]
      end
    end

    context "when only a position is supplied" do
      let(:interface) { Prawn::SVG::Interface.new(svg, prawn, position: position) }

      context "(:left)" do
        let(:position) { :left }
        it { is_expected.to eq [0, 600] }
      end

      context "(:center)" do
        let(:position) { :center }
        it { is_expected.to eq [275, 600] }
      end

      context "(:right)" do
        let(:position) { :right }
        it { is_expected.to eq [550, 600] }
      end

      context "a number" do
        let(:position) { 25.5 }
        it { is_expected.to eq [25.5, 600] }
      end
    end

    context "when a vposition is supplied" do
      let(:interface) { Prawn::SVG::Interface.new(svg, prawn, vposition: vposition) }

      context "(:top)" do
        let(:vposition) { :top }
        it { is_expected.to eq [0, 600] }
      end

      context "(:center)" do
        let(:vposition) { :center }
        it { is_expected.to eq [0, 350] }
      end

      context "(:bottom)" do
        let(:vposition) { :bottom }
        it { is_expected.to eq [0, 100] }
      end

      context "a number" do
        let(:vposition) { 25.5 }
        it { is_expected.to eq [0, 600 - 25.5] }
      end
    end
  end

  describe "#sizing and #resize" do
    let(:interface) { Prawn::SVG::Interface.new(svg, prawn, {}) }

    it "allows the advanced user to resize the SVG after learning about its dimensions" do
      expect(interface.sizing.output_width).to eq 250
      expect(interface.sizing.output_height).to eq 100

      interface.resize(width: 500)

      expect(interface.sizing.output_width).to eq 500
      expect(interface.sizing.output_height).to eq 200
    end
  end
end
