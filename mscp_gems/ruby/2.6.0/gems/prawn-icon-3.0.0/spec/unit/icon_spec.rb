# encoding: utf-8
#
# Copyright October 2014, Jesse Doyle. All rights reserved.
#
# This is free software. Please see the LICENSE and COPYING files for details.

require 'spec_helper'

describe Prawn::Icon do
  let(:errors) { described_class::Errors }
  let(:pdf) { create_pdf }

  describe '#initialize' do
    context 'valid icon family specifier' do
      it 'should be capable of creating icon instances' do
        icon = Prawn::Icon.new 'far-address-book', pdf

        expect(icon.unicode).to eq('')
      end

      it 'should raise an error if icon key is not found' do
        expect { Prawn::Icon.new('far-__INVALID__', pdf) }.to raise_error(
          errors::IconNotFound
        )
      end
    end

    context 'invalid icon specifier' do
      it 'should raise an error' do
        expect { pdf.icon('__INVALID__  some text') }.to raise_error(
          Prawn::Errors::UnknownFont
        )
      end
    end

    context 'without a pdf object' do
      it 'should raise an ArgumentError' do
        expect { Prawn::Icon.new('far-address-book') }.to raise_error(
          ArgumentError
        )
      end
    end
  end

  describe '#format_hash' do
    it 'should add :font and :content keys' do
      icon = Prawn::Icon.new 'far-address-book', pdf
      hash = icon.format_hash

      expect(hash[:font]).to eq('far')
      expect(hash[:content]).to eq('')
    end

    it 'should rename key :color to :text_color' do
      icon = Prawn::Icon.new 'far-address-book', pdf, color: '0099ff'
      hash = icon.format_hash

      expect(hash[:color]).to be_nil
      expect(hash[:text_color]).to eq('0099ff')
    end
  end

  describe '#render' do
    it 'should render an icon to the page' do
      pdf.icon('far-address-book').render
      text = PDF::Inspector::Text.analyze(pdf.render)

      expect(text.font_settings.first[:name]).to match(/FontAwesome/)
    end
  end

  describe '#set' do
    context 'with dashes in key' do
      it 'should return the set as a symbol from key' do
        set = Prawn::Icon.new('far-address-book', pdf).set

        expect(set).to eq(:far)
      end
    end

    context 'without dashes in key' do
      it 'raise an error about invalid keys' do
        expect { Prawn::Icon.new('some invalid key', pdf) }.to raise_error(
          Prawn::Errors::UnknownFont
        )
      end
    end
  end

  describe '#unicode' do
    context 'valid icon key' do
      it 'should return a unicode character' do
        icon = Prawn::Icon.new 'far-address-book', pdf

        expect(valid_unicode?(icon.unicode)).to be true
      end
    end

    context 'invalid icon key' do
      it 'should raise IconNotFound' do
        expect { Prawn::Icon.new('far-__INVALID__', pdf) }.to raise_error(
          errors::IconNotFound
        )
      end
    end
  end
end
