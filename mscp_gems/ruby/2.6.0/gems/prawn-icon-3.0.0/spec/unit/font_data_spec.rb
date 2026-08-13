# encoding: utf-8
#
# Copyright October 2014, Jesse Doyle. All rights reserved.
#
# This is free software. Please see the LICENSE and COPYING files for details.

require 'spec_helper'

describe Prawn::Icon::FontData do
  let(:pdf) { create_pdf }
  let(:fontawesome) { Prawn::Icon::FontData.new(pdf, set: :far) }

  before { Prawn::Icon::FontData.release_data }

  describe '#initialize' do
    before { Prawn::Icon::FontData.new(pdf, set: :far) }

    it 'should update font_families on initialization' do
      expect(pdf.font_families['far']).not_to be_nil
    end
  end

  describe '::load' do
    context 'specifier is a string' do
      let(:data) { Prawn::Icon::FontData.load(pdf, 'far') }

      it 'should load the font' do
        expect(data).not_to be_nil
      end

      it 'should only load a single object for multiple documents' do
        obj_id_1 = data.object_id
        second = Prawn::Icon::FontData.load(pdf, 'far')
        obj_id_2 = second.object_id

        expect(obj_id_1).to eq(obj_id_2)
      end
    end

    context 'specifier is a symbol' do
      let(:data) { Prawn::Icon::FontData.load(pdf, :far) }

      it 'should load the font' do
        expect(data).not_to be_nil
      end
    end
  end

  describe '::release_data' do
    it 'should remove all data references if requested' do
      Prawn::Icon::FontData.load(pdf, :far)
      Prawn::Icon::FontData.load(pdf, :fi)
      data = Prawn::Icon::FontData.release_data

      expect(data).to be_empty
    end
  end

  describe '::unicode_from_key' do
    it 'should provide a UTF-8 string for a valid key' do
      unicode = Prawn::Icon::FontData.unicode_from_key(pdf, 'far-address-book')
      valid = unicode.force_encoding('UTF-8').valid_encoding?

      expect(valid).to be true
    end
  end

  describe '::specifier_from_key' do
    it 'should provide the font specifier from a valid key' do
      specifier = Prawn::Icon::FontData.specifier_from_key('far-address-book')
      expect(specifier).to eq(:far)
    end

    it 'should error when key is nil' do
      expect { Prawn::Icon::FontData.specifier_from_key(nil) }.to raise_error(
        Prawn::Icon::Errors::IconKeyEmpty
      )
    end

    it 'should error when key is an empty string' do
      expect { Prawn::Icon::FontData.specifier_from_key('') }.to raise_error(
        Prawn::Icon::Errors::IconKeyEmpty
      )
    end

    it 'should handle strings without any dashes properly' do
      specifier = Prawn::Icon::FontData.specifier_from_key 'foo'

      expect(specifier).to eq(:foo)
    end
  end

  describe '#font_version' do
    it 'should have a font version as a string' do
      version = fontawesome.font_version

      expect(version).to be_a(String)
    end
  end

  describe '#legend_path' do
    it 'should have a valid path to a yml file for legend' do
      path = fontawesome.legend_path
      extname = File.extname(path)

      expect(extname).to eq('.yml')
    end
  end

  describe '#load_fonts' do
    it 'should return a FontData object' do
      ret_val = fontawesome.load_fonts(pdf)

      expect(ret_val).to be_a(Prawn::Icon::FontData)
    end
  end

  describe '#path' do
    it 'should have a valid path to a TTF file' do
      path = fontawesome.path
      extname = File.extname(path)

      expect(extname).to eq('.ttf')
    end
  end

  describe '#specifier' do
    it 'should retrieve the string specifier from the yaml legend file' do
      specifier = fontawesome.specifier

      expect(specifier).to eq('far')
    end
  end

  describe '#unicode' do
    it 'should provide a valid UTF-8 encoded string for a valid key' do
      unicode = fontawesome.unicode('address-book')
      valid = unicode.force_encoding('UTF-8').valid_encoding?

      expect(valid).to be true
    end

    it 'should raise an error if unable to match a key' do
      expect { fontawesome.unicode('an invalid sequence') }.to raise_error(
        Prawn::Icon::Errors::IconNotFound
      )
    end
  end

  describe '#keys' do
    it 'should return a non-empty array of strings' do
      keys = fontawesome.keys

      expect(keys).not_to be_empty
      expect(keys.first).to be_a(String)
    end

    it 'should not contain the version as a key' do
      keys = fontawesome.keys

      expect(keys.include?('__font_version__')).to be false
    end
  end

  describe '#yaml' do
    it 'should return a hash with the specifier as the first key' do
      yaml = fontawesome.yaml
      key = yaml.keys.first
      mapping = yaml['far']
      inner_key = mapping.keys.last
      inner_value = mapping.values.last
      proc = Proc.new { inner_value.force_encoding('UTF-8').valid_encoding? }

      expect(yaml).to be_a(Hash)
      expect(key).to eq('far')
      expect(inner_key).to be_a(String)
      expect(inner_value).to be_a(String)
      expect(proc.call).to be true
    end
  end
end
