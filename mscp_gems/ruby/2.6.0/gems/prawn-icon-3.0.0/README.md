# Prawn::Icon

[![Gem Version](https://badge.fury.io/rb/prawn-icon.svg)](http://badge.fury.io/rb/prawn-icon)
[![Build Status](https://api.travis-ci.org/jessedoyle/prawn-icon.svg?branch=master)](http://travis-ci.org/jessedoyle/prawn-icon)
[![Code Climate](https://codeclimate.com/github/jessedoyle/prawn-icon/badges/gpa.svg)](https://codeclimate.com/github/jessedoyle/prawn-icon)

Prawn::Icon provides a simple mechanism for rendering icons and icon fonts from within [Prawn](https://github.com/prawnpdf/prawn).

The following icon fonts ship with Prawn::Icon:

* FontAwesome (http://fontawesome.io/icons/)
* Foundation Icons (http://zurb.com/playground/foundation-icon-fonts-3)
* PaymentFont (https://paymentfont.com)

Prawn::Icon was originally written by Jesse Doyle.

## Installation

Prawn::Icon is distributed via RubyGems. You can install it with the following command:

```bash
gem install prawn-icon
```

## Usage

Prawn::Icon was designed to have an API familiar to Prawn. A single icon may be rendered as such:

```ruby
require 'prawn/icon'

Prawn::Document.generate('icons.pdf') do |pdf|
  pdf.icon 'fas-beer', size: 60
end
```

produces:

![FontAwesome Beer](https://raw.github.com/jessedoyle/prawn-icon/master/examples/fas-beer.png)

## Inline Icons

You can also provide the `inline_format: true` option to Prawn::Icon:

```ruby
require 'prawn/icon'

Prawn::Document.generate('inline_icons.pdf') do |pdf|
  pdf.icon 'Enjoy: <icon size="20" color="AAAAAA">fas-beer</icon>', inline_format: true
end
```

produces:

![FontAwesome Beer Inline](https://raw.github.com/jessedoyle/prawn-icon/master/examples/fas-beer-inline.png)

When using `inline_format: true`, you may supply `<icon>` tags with `color` and `size` attributes.

## Use with [Prawn::Table](https://github.com/prawnpdf/prawn-table)

A `table_icon` method may be called when creating a table's data array to render icons within a table cell:

```ruby
require 'prawn/icon'
require 'prawn/table'

Prawn::Document.generate('table_icons.pdf') do |pdf|

  data = [
    # Explicit brackets must be used here
    [pdf.table_icon('fas-birthday-cake'), 'Cake'],
    ['is', 'Great!']
  ]

  pdf.table(data) # => (2 x 2 table)
end
```

Note that the `table_icon` method supports the `inline_format: true` option to create multiple icons within a cell.

## Specifying Icon Families

Prawn::Icon uses the prefix of an icon key to determine which font family is used to render a particular icon.

Currently supported prefixes include:

* `fab` - [FontAwesome Brands](https://fontawesome.com/icons?d=gallery&s=brands&m=free) (eg. `fab-amazon`).
* `far` - [FontAwesome Regular](https://fontawesome.com/icons?d=gallery&s=regular&m=free) (eg. `far-address-book`).
* `fas` - [FontAwesome Solid](https://fontawesome.com/icons?d=gallery&s=solid&m=free) (eg. `fas-location-arrow`).
* `fi` - [Foundation Icons](https://zurb.com/playground/foundation-icon-fonts-3) (eg. `fi-compass`).
* `pf` - [PaymentFont](https://paymentfont.com/#icons) (eg. `pf-cash`).

## How It Works

Prawn::Icon uses a "legend" to map icon keys to unicode characters that respresent a particular icon within the font file.

This legend is a standard `.yml` file located within the font's directory.

If you wish to fork this repository and add a new font, you'll likely need to supply a corresponding legend file. Please see the current legend files within the `data/fonts` directory for examples.

## Examples

A Rake task is included to generate documents that display each icon and it's corresponding icon key.

The command:

```bash
rake legend
```

should generate these files when run from Prawn::Icon's gem directory.

## Configuration

You can optionally configure Prawn::Icon to use an alternate data directory for font files.

```ruby
Prawn::Icon.configure do |config|
  config.font_directory = '/path/to/my/fonts'
end
```

## Contributing

I'll gladly accept pull requests that are well tested for any bug found in Prawn::Icon.

If there is enough demand for including a particular icon font, I will also accept a pull request to include it in Prawn::Icon.

## License

Prawn::Icon is licensed under the same terms that are used by Prawn.

You may choose between Matz's terms, the GPLv2, or GPLv3. For details, please see the LICENSE, GPLv2, and GPLv3 files.
