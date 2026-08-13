# All example code may be executed by calling `rake legend`

require_relative '../lib/prawn/icon'
require_relative 'example_helper'

STYLES = {
  fab: 'Brands',
  far: 'Regular',
  fas: 'Solid'
}.freeze

STYLES.each do |specifier, type|
  Prawn::Document.generate("fontawesome_#{type.downcase}.pdf") do
    deja_path = Prawn::Icon.configuration.font_directory
      .join('DejaVuSans.ttf')
      .to_s

    font_families.update(
      'deja' => { normal: deja_path }
    )

    font('deja')

    icons = icon_keys(self, specifier.to_s)
    required_pages = number_of_pages(self, specifier.to_s)

    define_grid(columns: 6, rows: 12, gutter: 16)

    sub_header = "FontAwesome | #{type}"
    link = 'http://fontawesome.io/icons/'
    page_header sub_header, link

    first_page_icons icons do |icon_key|
      # Just call the +icon+ method and pass in an icon key
      icon icon_key, size: 20, align: :center
    end

    start_new_page

    page_icons icons, required_pages do |icon_key|
      icon icon_key, size: 20, align: :center
    end
  end
end
