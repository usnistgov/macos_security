require 'spec_helper'

RSpec.describe Prawn::SVG::Loaders::Data do
  let(:uri) { URI(url) }

  subject { Prawn::SVG::Loaders::Data.new.from_url(url) }

  context "with a valid image/png data URL" do
    let(:url) { "data:image/png;base64,aGVsbG8=" }

    it "loads the data" do
      expect(subject).to eq "hello"
    end
  end

  context "with a valid image/jpeg data URL" do
    let(:url) { "data:image/jpeg;base64,aGVsbG8=" }

    it "loads the data" do
      expect(subject).to eq "hello"
    end
  end

  context "with a data URL that has extra metadata" do
    let(:url) { "data:image/png;base64;metadata;here,aGVsbG8=" }

    it "loads the data" do
      expect(subject).to eq "hello"
    end
  end

  context "with a data URL that's uppercase" do
    let(:url) { "DATA:IMAGE/PNG;BASE64;METADATA;HERE,aGVsbG8=" }

    it "loads the data" do
      expect(subject).to eq "hello"
    end
  end

  context "with a URL that's not a data scheme" do
    let(:url) { "http://some.host" }

    it "returns nil" do
      expect(subject).to be nil
    end
  end

  context "with a data URL that's not an image" do
    let(:url) { "data:application/pdf;base64,aGVsbG8=" }

    it "raises" do
      expect { subject }.to raise_error Prawn::SVG::UrlLoader::Error, /image/
    end
  end

  context "with a data URL that's not base64 encoded" do
    let(:url) { "data:image/png;base32,agvsbg" }

    it "raises" do
      expect { subject }.to raise_error Prawn::SVG::UrlLoader::Error, /base64/
    end
  end
end
