# encoding: utf-8
#
# Copyright October 2014, Jesse Doyle. All rights reserved.
#
# This is free software. Please see the LICENSE and COPYING files for details.

require 'spec_helper'

describe Prawn::Icon::Interface do
  let(:pdf) { create_pdf }

  describe '::icon' do
    context 'valid icon key' do
      context 'with options' do
        it 'should handle text options (size)' do
          pdf.icon 'far-address-book', size: 60
          text = PDF::Inspector::Text.analyze(pdf.render)

          expect(text.font_settings.first[:size]).to eq(60)
        end
      end

      context 'inline_format: true' do
        it 'should handle text options (size)' do
          pdf.icon '<icon size="60">far-address-book</icon>', inline_format: true
          text = PDF::Inspector::Text.analyze(pdf.render)

          expect(text.strings.first).to eq('')
          expect(text.font_settings.first[:size]).to eq(60.0)
        end

        it 'should be able to render on multiple documents' do
          pdf1 = create_pdf
          pdf2 = create_pdf
          pdf1.icon '<icon>far-address-book</icon>', inline_format: true
          pdf2.icon '<icon>far-address-book</icon>', inline_format: true
          text1 = PDF::Inspector::Text.analyze(pdf1.render)
          text2 = PDF::Inspector::Text.analyze(pdf2.render)

          expect(text1.strings.first).to eq('')
          expect(text2.strings.first).to eq('')
        end

        it 'renders the icon at the proper cursor position (#24)' do
          icon_text = '<icon>fas-info-circle</icon> icon here!'
          pdf.text 'Start'
          pdf.move_down 10
          pdf.text 'More'
          pdf.move_down 20
          pdf.icon icon_text, inline_format: true
          pdf.move_down 30
          pdf.text 'End'
          inspector = PDF::Inspector::Text.analyze(pdf.render)
          x, y = inspector.positions[2]

          expect(x).to eq(0)
          expect(y.round).to eq(724)
        end

        context 'with final_gap: false' do
          it 'renders the icon without a final gap' do
            pdf.icon(
              '<icon size="60">far-address-book</icon>',
              inline_format: true,
              final_gap: false
            )
            pdf.text('Hello')
            inspector = PDF::Inspector::Text.analyze(pdf.render)
            y = inspector.positions[1].last.round

            expect(y).to eq(723)
          end
        end
      end

      context 'without options' do
        it 'should render an icon to document' do
          pdf.icon 'far-address-book'
          text = PDF::Inspector::Text.analyze(pdf.render)

          expect(text.strings.first).to eq('')
        end
      end
    end

    context 'invalid icon key' do
      it 'should raise IconNotFound' do
        expect { pdf.icon('far-__INVALID') }.to raise_error(
          Prawn::Icon::Errors::IconNotFound
        )
      end
    end

    context 'invalid specifier' do
      it 'should raise UnknownFont' do
        expect { pdf.icon('__INVALID__') }.to raise_error(
          Prawn::Errors::UnknownFont
        )
      end
    end
  end

  describe '::make_icon' do
    context ':inline_format => false (default)' do
      it 'should return a Prawn::Icon instance' do
        icon = pdf.make_icon 'far-address-book'

        expect(icon).to be_a(Prawn::Icon)
      end
    end

    context ':inline_format => true' do
      it 'returns nil' do
        icon = pdf.make_icon '<icon>far-address-book</icon>', inline_format: true

        expect(icon).to be_nil
      end
    end
  end

  describe '::inline_icon' do
    it 'returns nil' do
      icon = pdf.inline_icon '<icon>far-address-book</icon>'

      expect(icon).to be_nil
    end

    it 'starts a new page if necessary', github_issue: '49' do
      text = 209.times.map { 'Hello, World!' }.join(' ')
      pdf.text(text, size: 18)
      pdf.icon('Hello, <icon>fas-globe</icon>', inline_format: true, size: 18)
      inspector = PDF::Inspector::Page.analyze(pdf.render)

      expect(inspector.pages.size).to eq(2)
    end
  end

  describe '::formatted_icon_box' do
    it 'returns a Prawn::Text::Formatted::Box instance' do
      icon_text = <<~CONTENT
        <icon size="20">fas-broom</icon>
        <strikethrough>cancel that</strikethrough>
        <icon>fas-check</icon>
      CONTENT
      box = pdf.formatted_icon_box(icon_text, inline_format: true)

      expect(box).to be_a(Prawn::Text::Formatted::Box)
    end

    it 'accepts an absolute position parameter' do
      icon_text = 'Hello, <icon>fas-globe</icon>!'
      pdf.formatted_icon_box(icon_text, inline_format: true, x: 200, y: 100).render
      inspector = PDF::Inspector::Text.analyze(pdf.render)
      x, y = inspector.positions[0]

      expect(x).to eq(200)
      expect(y.round).to eq(90)
    end

    it 'handles final_gap: false correctly' do
      icon_text = <<~CONTENT
        Hello, <icon size="60">fas-globe</icon>
        Next line.
      CONTENT
      pdf.formatted_icon_box(icon_text, inline_format: true, final_gap: false).render
      inspector = PDF::Inspector::Text.analyze(pdf.render)
      x = inspector.positions[1].first

      expect(x.round).to eq(34)
    end
  end

  describe '::table_icon' do
    context 'inline_format: false (default)' do
      it 'should return a hash with font and content keys' do
        icon = pdf.table_icon 'far-address-book'

        expect(icon).to be_a(Hash)
        expect(icon[:font]).to eq('far')
        expect(icon[:content]).to eq('')
      end
    end

    context 'inline_format: true' do
      it 'should convert <icon> to <font> tags' do
        icon = pdf.table_icon '<icon>fas-user</icon>', inline_format: true

        expect(icon).to be_a(Hash)
        expect(icon[:content]).to eq('<font name="fas"></font>')
        expect(icon[:inline_format]).to be true
      end

      it 'should ignore all other tags' do
        a = ['<b>BOLD</b> <color rgb="0099FF">BLUE</color>', inline_format: true]
        icon = pdf.table_icon(*a)

        expect(icon).to be_a(Hash)
        expect(icon[:content]).to eq(a[0])
        expect(icon[:inline_format]).to be true
      end

      context 'multiple icons' do
        it 'should ignore any text not in an icon tag' do
          a = ['<icon>fas-user</icon> Some Text <icon>fi-laptop</icon>', inline_format: true]
          out = '<font name="fas"></font> Some Text <font name="fi"></font>'
          icon = pdf.table_icon(*a)

          expect(icon).to be_a(Hash)
          expect(icon[:content]).to eq(out)
          expect(icon[:inline_format]).to be true
        end
      end
    end
  end
end

describe Prawn::Icon do
  let(:pdf) { create_pdf }

  context 'FontAwesome | Regular' do
    it 'should render regular glyphs' do
      pdf.icon 'far-user'
      text = PDF::Inspector::Text.analyze(pdf.render)

      expect(text.strings.first).to eq('')
    end
  end

  context 'FontAwesome | Solid' do
    it 'should render solid glyphs' do
      pdf.icon 'fas-user'
      text = PDF::Inspector::Text.analyze(pdf.render)

      expect(text.strings.first).to eq('')
    end
  end

  context 'FontAwesome | Brands' do
    it 'should render FontAwesome glyphs' do
      pdf.icon 'fab-amazon'
      text = PDF::Inspector::Text.analyze(pdf.render)

      expect(text.strings.first).to eq('')
    end
  end

  context 'Foundation Icons' do
    it 'should render Foundation glyphs' do
      pdf.icon 'fi-laptop'
      text = PDF::Inspector::Text.analyze(pdf.render)

      expect(text.strings.first).to eq('')
    end
  end

  context 'PaymentFont' do
    it 'should render PaymentFont glyphs' do
      pdf.icon 'pf-amazon'
      text = PDF::Inspector::Text.analyze(pdf.render)

      expect(text.strings.first).to eq('')
    end
  end
end
