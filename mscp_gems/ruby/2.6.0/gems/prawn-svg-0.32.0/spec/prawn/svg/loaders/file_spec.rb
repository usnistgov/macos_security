require 'spec_helper'

RSpec.describe Prawn::SVG::Loaders::File do
  let(:root_path) { "." }
  let(:fake_root_path) { "/some" }

  let(:file_loader) { Prawn::SVG::Loaders::File.new(root_path) }
  subject { file_loader.from_url(url) }

  context "when an invalid path is supplied" do
    let(:root_path) { "/does/not/exist" }

    it "raises with an ArgumentError" do
      expect { subject }.to raise_error ArgumentError, /is not a directory/
    end
  end

  context "when a relative path is supplied" do
    let(:url) { "relative/./path" }

    it "loads the file" do
      expect(File).to receive(:expand_path).with(".").and_return(fake_root_path)
      expect(File).to receive(:expand_path).with("relative/./path", fake_root_path).and_return("#{fake_root_path}/relative/path")

      expect(Dir).to receive(:exist?).with(fake_root_path).and_return(true)
      expect(File).to receive(:exist?).with("#{fake_root_path}/relative/path").and_return(true)
      expect(IO).to receive(:binread).with("#{fake_root_path}/relative/path").and_return("data")

      expect(subject).to eq 'data'
    end
  end

  context "when an absolute path without file scheme is supplied" do
    let(:url) { "/some/absolute/./path" }

    it "loads the file" do
      expect(File).to receive(:expand_path).with(".").and_return(fake_root_path)
      expect(File).to receive(:expand_path).with(url, fake_root_path).and_return("/some/absolute/path")

      expect(Dir).to receive(:exist?).with(fake_root_path).and_return(true)
      expect(File).to receive(:exist?).with("/some/absolute/path").and_return(true)
      expect(IO).to receive(:binread).with("/some/absolute/path").and_return("data")

      expect(subject).to eq 'data'
    end
  end

  context "when an absolute path with file scheme is supplied" do
    let(:url) { "file:///some/absolute/./path%20name" }

    it "loads the file" do
      expect(File).to receive(:expand_path).with(".").and_return(fake_root_path)
      expect(File).to receive(:expand_path).with("/some/absolute/./path name", fake_root_path).and_return("/some/absolute/path name")

      expect(Dir).to receive(:exist?).with(fake_root_path).and_return(true)
      expect(File).to receive(:exist?).with("/some/absolute/path name").and_return(true)
      expect(IO).to receive(:binread).with("/some/absolute/path name").and_return("data")

      expect(subject).to eq 'data'
    end
  end

  context "when a path outside of our root is specified" do
    let(:url) { "/other/absolute/./path" }

    it "raises" do
      expect(File).to receive(:expand_path).with(".").and_return(fake_root_path)
      expect(File).to receive(:expand_path).with(url, fake_root_path).and_return("/other/absolute/path")

      expect(Dir).to receive(:exist?).with(fake_root_path).and_return(true)

      expect { subject }.to raise_error Prawn::SVG::UrlLoader::Error, /not inside the root path/
    end
  end

  context "when a file: url with a host is specified" do
    let(:url) { "file://somewhere/somefile" }

    it "raises" do
      expect(File).to receive(:expand_path).with(".").and_return(fake_root_path)
      expect(Dir).to receive(:exist?).with(fake_root_path).and_return(true)

      expect { subject }.to raise_error Prawn::SVG::UrlLoader::Error, /with a host/
    end
  end

  context "when we're running on Windows" do
    let(:url) { "file:///c:/path/to/file.png" }
    let(:fake_root_path) { "c:/full" }

    it "automatically fixes up URI's misparsing of Windows file paths and loads the file" do
      expect(File).to receive(:expand_path).with(".").and_return(fake_root_path)
      expect(File).to receive(:expand_path).with("c:/path/to/file.png", fake_root_path).and_return("c:/full/path/to/file.png")

      expect(Dir).to receive(:exist?).with(fake_root_path).and_return(true)
      expect(File).to receive(:exist?).with("c:/full/path/to/file.png").and_return(true)
      expect(IO).to receive(:binread).with("c:/full/path/to/file.png").and_return("data")

      allow(file_loader).to receive(:windows?).and_return true
      expect(subject).to eq 'data'
    end
  end
end
