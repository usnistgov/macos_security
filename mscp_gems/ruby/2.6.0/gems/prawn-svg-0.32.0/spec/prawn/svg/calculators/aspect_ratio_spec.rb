require File.dirname(__FILE__) + '/../../../spec_helper'

describe Prawn::SVG::Calculators::AspectRatio do
  def test(*args)
    aspect = Prawn::SVG::Calculators::AspectRatio.new(*args)
    [[aspect.width, aspect.height], [aspect.x, aspect.y]]
  end

  it "handles none" do
    expect(test "none", [50,80], [100,100]).to eq [[50, 80], [0, 0]]
    expect(test "none", [100,100], [50,80]).to eq [[100, 100], [0, 0]]
  end

  context "using meet" do
    context "with smaller containers than objects" do
      let(:coords) { [[50,80], [100,100]] }

      it "correctly calculates the result" do
        expect(test "xMidYMid meet", *coords).to eq [[50, 50], [0, 15]]
        expect(test "xMinYMin meet", *coords).to eq [[50, 50], [0, 0]]
        expect(test "xMaxYMax meet", *coords).to eq [[50, 50], [0, 30]]
      end
    end

    context "with bigger containers than objects" do
      let(:coords) { [[100,80], [50,50]] }

      it "correctly calculates the result" do
        expect(test "xMidYMid meet", *coords).to eq [[80, 80], [10, 0]]
        expect(test "xMinYMin meet", *coords).to eq [[80, 80], [0, 0]]
        expect(test "xMaxYMax meet", *coords).to eq [[80, 80], [20, 0]]
      end
    end

    context "with bigger square containers" do
      let(:coords) { [[100,100], [50,80]] }

      it "correctly calculates the result" do
        expect(test "xMidYMid meet", *coords).to eq [[62.5, 100], [18.75, 0]]
        expect(test "xMinYMin meet", *coords).to eq [[62.5, 100], [0, 0]]
        expect(test "xMaxYMax meet", *coords).to eq [[62.5, 100], [37.5, 0]]
      end
    end

    context "with oddly shaped containers" do
      let(:coords) { [[100,20], [50,50]] }

      it "correctly calculates the result" do
        expect(test "xMidYMid meet", *coords).to eq [[20, 20], [40, 0]]
        expect(test "xMinYMin meet", *coords).to eq [[20, 20], [0, 0]]
        expect(test "xMaxYMax meet", *coords).to eq [[20, 20], [80, 0]]
      end
    end
  end

  context "using slice" do
    context "with smaller containers than objects" do
      let(:coords) { [[50,80], [100,100]] }

      it "correctly calculates the result" do
        expect(test "xMidYMid slice", *coords).to eq [[80, 80], [-15, 0]]
        expect(test "xMinYMin slice", *coords).to eq [[80, 80], [0, 0]]
        expect(test "xMaxYMax slice", *coords).to eq [[80, 80], [-30, 0]]
      end
    end

    context "with bigger containers than objects" do
      let(:coords) { [[100,80], [50,50]] }

      it "correctly calculates the result" do
        expect(test "xMidYMid slice", *coords).to eq [[100, 100], [0, -10]]
        expect(test "xMinYMin slice", *coords).to eq [[100, 100], [0, 0]]
        expect(test "xMaxYMax slice", *coords).to eq [[100, 100], [0, -20]]
      end
    end

    context "with oddly shaped containers" do
      let(:coords) { [[100,20], [50,50]] }

      it "correctly calculates the result" do
        expect(test "xMidYMid slice", *coords).to eq [[100, 100], [0, -40]]
        expect(test "xMinYMin slice", *coords).to eq [[100, 100], [0, 0]]
        expect(test "xMaxYMax slice", *coords).to eq [[100, 100], [0, -80]]
      end
    end
  end

  it "defaults to 'xMidYMid meet' if nothing is supplied" do
    expect(test "", [50,80], [100,100]).to eq test "xMidYMid meet", [50,80], [100,100]
  end

  it "defaults to 'xMidYMid meet' if something invalid is supplied" do
    expect(test "completely invalid", [50,80], [100,100]).to eq test "xMidYMid meet", [50,80], [100,100]
  end
end
