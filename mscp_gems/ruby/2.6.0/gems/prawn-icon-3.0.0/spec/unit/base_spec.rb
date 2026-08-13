# encoding: utf-8
#
# Copyright September 2016, Jesse Doyle. All rights reserved.
#
# This is free software. Please see the LICENSE and COPYING files for details.

describe Prawn::Icon do
  describe '#configuration' do
    it 'returns an instance of Prawn::Icon::Configuration' do
      expect(described_class.configuration).to be_a(Prawn::Icon::Configuration)
    end
  end

  describe '#configure' do
    around(:each) do |example|
      old = described_class.configuration.dup
      described_class.configure do |config|
        config.font_directory = '/tmp/fonts'
      end
      example.run
      described_class.configuration = old
    end

    it 'yields control' do
      expect { |b| described_class.configure(&b) }.to yield_control
    end

    it 'configures properties' do
      expect(described_class.configuration.font_directory).to eq(
        Pathname.new('/tmp/fonts')
      )
    end
  end
end
