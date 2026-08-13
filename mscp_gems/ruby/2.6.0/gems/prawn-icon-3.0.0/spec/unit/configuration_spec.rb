# encoding: utf-8
#
# Copyright October 2020, Jesse Doyle. All rights reserved.
#
# This is free software. Please see the LICENSE and COPYING files for details.

describe Prawn::Icon::Configuration do
  describe '#font_directory' do
    before(:each) do
      subject.font_directory = '/tmp/fakedir'
    end

    it 'returns a Pathname' do
      expect(subject.font_directory).to be_a(Pathname)
    end

    it 'returns the configured path' do
      expect(subject.font_directory.to_s).to eq('/tmp/fakedir') 
    end
  end
end
