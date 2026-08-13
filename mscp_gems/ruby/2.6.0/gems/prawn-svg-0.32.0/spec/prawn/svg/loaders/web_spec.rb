require 'spec_helper'

RSpec.describe Prawn::SVG::Loaders::Web do
  let(:url) { "http://hello.there/path" }
  let(:uri) { URI(url) }

  subject { Prawn::SVG::Loaders::Web.new.from_url(url) }

  it "loads an HTTP URL" do
    expect(Net::HTTP).to receive(:get).with(uri).and_return("hello!")
    expect(subject).to eq "hello!"
  end

  context "with an https URL" do
    let(:url) { "https://hello.there/path"}

    it "loads the HTTPS URL" do
      expect(Net::HTTP).to receive(:get).with(uri).and_return("hello!")
      expect(subject).to eq "hello!"
    end
  end

  context "when the HTTP call raises" do
    it "re-raises the error as UrlLoader errors" do
      expect(Net::HTTP).to receive(:get).with(uri).and_raise(SocketError, "argh")
      expect { subject }.to raise_error Prawn::SVG::UrlLoader::Error, 'argh'
    end
  end

  context "with a non-http, non-https URL" do
    let(:url) { "mailto:someone@something" }

    it "returns nil" do
      expect(subject).to be nil
    end
  end
end
