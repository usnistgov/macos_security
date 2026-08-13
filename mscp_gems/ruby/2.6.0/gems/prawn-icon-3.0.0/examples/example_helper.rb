# encoding: utf-8
#
# example_helper.rb: Helper used to generate icon font legends.
#
# Copyright October 2014, Jesse Doyle. All rights reserved.
#
# This is free software. Please see the LICENSE and COPYING files for details.

# All example code may be executed by calling `rake legend`

ICONS_PER_PAGE = 72

def icon_keys(pdf, specifier)
  keys = Prawn::Icon::FontData.load(pdf, specifier).keys
  keys.each_slice(6).to_a
end

def page_header(text, link)
  grid([0, 0], [1, 5]).bounding_box do
    move_down 10
    text 'Prawn/Icon', size: 50

    if block_given?
      yield
    else
      text "#{text}: <color rgb='1B83BE'>" +
            "<link href='#{link}'>#{link}</link></color>",
            inline_format: true,
            size: 12
    end
  end
end

def number_of_pages(pdf, specifier)
  keys = Prawn::Icon::FontData.load(pdf, specifier).keys
  num_icons = keys.size

  # First page can only fit 60 icons
  num_icons -= 60

  # (First page) + (remaining pages)
  1 + (num_icons/ICONS_PER_PAGE).ceil
end

def legend_text(key)
  h = cursor - bounds.bottom
  opts = {
    width: bounds.width,
    height: h
  }

  bounding_box [bounds.left, cursor], opts do
    text key,
         overflow: :shrink_to_fit,
         align: :center,
         valign: :bottom,
         width: bounds.width,
         height: bounds.height,
         size: 12
  end
end

def first_page_icons(icons)
  icons[0..9].each_with_index do |group, i|
    group.each_with_index do |icon, j|
      grid(i+2, j).bounding_box do

        if block_given?
          yield icon
        else
          icon icon, size: 20, align: :center
        end

        move_down 4

        legend_text icon
      end
    end
  end

  def page_icons(icons, required_pages)
    icon_start = 10 # Skip first page icons
    required_pages.times do |page|
      icons[icon_start..icon_start+11].each_with_index do |group, i|
        group.each_with_index do |icon, j|
          grid(i, j).bounding_box do

            if block_given?
              yield icon
            else
              icon icon, size: 20, align: :center
            end

            move_down 4

            legend_text icon
          end
        end
        icon_start += 1 # New icon row
      end

      start_new_page unless page == required_pages - 1
    end
  end
end
