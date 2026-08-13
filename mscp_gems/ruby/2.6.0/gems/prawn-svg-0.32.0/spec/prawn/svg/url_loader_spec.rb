require 'spec_helper'

describe Prawn::SVG::UrlLoader do
  let(:enable_cache) { true }
  let(:enable_web)   { true }
  let(:enable_file)  { "." }
  let(:loader) { Prawn::SVG::UrlLoader.new(enable_cache: enable_cache, enable_web: enable_web, enable_file_with_root: enable_file) }

  describe "#initialize" do
    it "sets options" do
      expect(loader.enable_cache).to be true
    end
  end

  describe "#load" do
    let(:url) { "http://hello/there" }
    let(:data_loader) { instance_double(Prawn::SVG::Loaders::Data) }
    let(:web_loader) { instance_double(Prawn::SVG::Loaders::Web) }
    let(:file_loader) { instance_double(Prawn::SVG::Loaders::File) }

    before do
      allow(Prawn::SVG::Loaders::Data).to receive(:new).and_return(data_loader)
      allow(Prawn::SVG::Loaders::Web).to receive(:new).and_return(web_loader)
      allow(Prawn::SVG::Loaders::File).to receive(:new).with(enable_file).and_return(file_loader)
    end

    subject { loader.load(url) }

    it "calls the Data loader and returns its output if successful" do
      expect(data_loader).to receive(:from_url).with(url).and_return("data")
      expect(web_loader).not_to receive(:from_url)

      expect(subject).to eq 'data'
    end

    it "calls the Web loader if the Data loader returns nothing, and returns its output if successful" do
      expect(data_loader).to receive(:from_url).with(url)
      expect(web_loader).to receive(:from_url).with(url).and_return("data")

      expect(subject).to eq 'data'
    end

    it "calls the File loader if the Data and Web loaders return nothing, and returns its output if successful" do
      expect(data_loader).to receive(:from_url).with(url)
      expect(web_loader).to receive(:from_url).with(url)
      expect(file_loader).to receive(:from_url).with(url).and_return("data")

      expect(subject).to eq 'data'
    end

    it "raises if none of the loaders return any data" do
      expect(data_loader).to receive(:from_url).with(url)
      expect(web_loader).to receive(:from_url).with(url)
      expect(file_loader).to receive(:from_url).with(url)

      expect { subject }.to raise_error(Prawn::SVG::UrlLoader::Error, /No handler available/)
    end

    context "when caching is enabled" do
      it "caches the result" do
        expect(data_loader).to receive(:from_url).with(url).and_return("data")
        expect(subject).to eq 'data'
        expect(loader.retrieve_from_cache(url)).to eq 'data'
      end
    end

    context "when caching is disabled" do
      let(:enable_cache) { false }

      it "does not cache the result" do
        expect(data_loader).to receive(:from_url).with(url).and_return("data")
        expect(subject).to eq 'data'
        expect(loader.retrieve_from_cache(url)).to be nil
      end
    end

    context "when the cache is populated" do
      before { loader.add_to_cache(url, 'data') }

      it "returns the cached value without calling a loader" do
        expect(data_loader).not_to receive(:from_url)
        expect(web_loader).not_to receive(:from_url)

        expect(subject).to eq 'data'
      end
    end

    context "when web requests are disabled" do
      let(:enable_web) { false }

      it "doesn't use the web loader" do
        expect(data_loader).to receive(:from_url)
        expect(web_loader).not_to receive(:from_url)
        expect(file_loader).to receive(:from_url)

        expect { subject }.to raise_error(Prawn::SVG::UrlLoader::Error, /No handler available/)
      end
    end

    context "when file requests are disabled" do
      let(:enable_file) { nil }

      it "doesn't use the file loader" do
        expect(data_loader).to receive(:from_url)
        expect(web_loader).to receive(:from_url)
        expect(file_loader).not_to receive(:from_url)

        expect { subject }.to raise_error(Prawn::SVG::UrlLoader::Error, /No handler available/)
      end
    end
  end
end
