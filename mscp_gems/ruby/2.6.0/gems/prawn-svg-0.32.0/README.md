# prawn-svg

[![Gem Version](https://badge.fury.io/rb/prawn-svg.svg)](https://badge.fury.io/rb/prawn-svg)
![Build Status](https://github.com/mogest/prawn-svg/actions/workflows/test.yml/badge.svg?branch=master)

An SVG renderer for the Prawn PDF library.

This will take an SVG document as input and render it into your PDF.  Find out more about the Prawn PDF library at:

  http://github.com/prawnpdf/prawn

prawn-svg is compatible with all versions of Prawn from 0.11.1 onwards, including the 1.x and 2.x series.
The minimum Ruby version required is 2.3.0.

## Using prawn-svg

```ruby
Prawn::Document.generate("test.pdf") do
  svg '<svg><rect width="100" height="100" fill="red"></rect></svg>'
end
```

prawn-svg will do something sensible if you call it with only an SVG document, but you can also
pass the following options to tailor its operation:

Option      | Data type | Description
----------- | --------- | -----------
:at         | [integer, integer] | Specify the location on the page you want the SVG to appear.
:position   | :left, :center, :right, integer | If :at not specified, specifies the horizontal position to show the SVG.  Defaults to :left.
:vposition  | :top, :center, :bottom, integer | If :at not specified, specifies the vertical position to show the SVG.  Defaults to current cursor position.
:width      | integer   | Desired width of the SVG.  Defaults to horizontal space available.
:height     | integer   | Desired height of the SVG.  Defaults to vertical space available.
:enable_web_requests | boolean | If true, prawn-svg will make http and https requests to fetch images.  Defaults to true.
:enable_file_requests_with_root | string | If not nil, prawn-svg will serve `file:` URLs from your local disk if the file is located under the specified directory. It is very dangerous to specify the root path ("/") if you're not fully in control of your input SVG.  Defaults to `nil` (off).
:cache_images | boolean   | If true, prawn-svg will cache the result of all URL requests. Defaults to false.
:fallback_font_name | string | A font name which will override the default fallback font of Times-Roman.  If this value is set to <tt>nil</tt>, prawn-svg will ignore a request for an unknown font and log a warning.

## Examples

```ruby
  # Render the logo contained in the file logo.svg at 100, 100 with a width of 300
  svg IO.read("logo.svg"), at: [100, 100], width: 300

  # Render the logo at the current Y cursor position, centered in the current bounding box
  svg IO.read("logo.svg"), position: :center

  # Render the logo at the current Y cursor position, and serve file: links relative to its directory
  root_path = "/apps/myapp/current/images"
  svg IO.read("#{root_path}/logo.svg"), enable_file_requests_with_root: root_path
```

## Supported features

prawn-svg supports most but not all of the full SVG 1.1 specification.  It currently supports:

 - <tt>&lt;line&gt;</tt>, <tt>&lt;polyline&gt;</tt>, <tt>&lt;polygon&gt;</tt>, <tt>&lt;circle&gt;</tt> and <tt>&lt;ellipse&gt;</tt>

 - <tt>&lt;rect&gt;</tt>.  Rounded rects are supported, but only one radius is applied to all corners.

 - <tt>&lt;path&gt;</tt> supports all commands defined in SVG 1.1, although the
   implementation of elliptical arc is a bit rough at the moment.

 - `<text>`, `<tspan>` and `<tref>` with attributes `x`, `y`, `dx`, `dy`, `rotate`, 'textLength', 'lengthAdjust', and with extra properties
   `text-anchor`, `text-decoration` (underline only), `font-size`, `font-family`, `font-weight`, `font-style`, `letter-spacing`

 - <tt>&lt;svg&gt;</tt>, <tt>&lt;g&gt;</tt> and <tt>&lt;symbol&gt;</tt>

 - <tt>&lt;use&gt;</tt>

 - <tt>&lt;style&gt;</tt> (see CSS section below)

 - <tt>&lt;image&gt;</tt> with <tt>http:</tt>, <tt>https:</tt>, <tt>data:image/\*;base64</tt> and `file:` schemes
   (`file:` is disabled by default for security reasons, see Options section above)

 - <tt>&lt;clipPath&gt;</tt>

 - `<marker>`

 - `<linearGradient>` and `<radialGradient>` are implemented on Prawn 2.2.0+ with attributes `gradientUnits` and `gradientTransform` (spreadMethod and stop-opacity are unimplemented.)

 - `<switch>` and `<foreignObject>`, although prawn-svg cannot handle any data that is not SVG so `<foreignObject>`
   tags are always ignored.

 - properties: `clip-path`, `color`, `display`, `fill`, `fill-opacity`, `fill-rule`, `opacity`, `overflow`, `stroke`, `stroke-dasharray`, `stroke-linecap`, `stroke-opacity`, `stroke-width`

 - properties on lines, polylines, polygons and paths: `marker-end`, `marker-mid`, `marker-start`

 - attributes on all elements: `class`, `id`, `style`, `transform`, `xml:space`

 - the <tt>viewBox</tt> attribute on <tt>&lt;svg&gt;</tt> and `<marker>` elements

 - the <tt>preserveAspectRatio</tt> attribute on <tt>&lt;svg&gt;</tt>, <tt>&lt;image&gt;</tt> and `<marker>` elements

 - transform methods: `translate`, `translateX`, `translateY`, `rotate`, `scale`, `skewX`, `skewY`, `matrix`

 - colors: HTML standard names, <tt>#xxx</tt>, <tt>#xxxxxx</tt>, <tt>rgb(1, 2, 3)</tt>, <tt>rgb(1%, 2%, 3%)</tt>

 - measurements specified in <tt>pt</tt>, <tt>cm</tt>, <tt>dm</tt>, <tt>ft</tt>, <tt>in</tt>, <tt>m</tt>, <tt>mm</tt>, <tt>yd</tt>, <tt>pc</tt>, <tt>%</tt>

 - fonts: generic CSS fonts, built-in PDF fonts, and any TTF fonts in your fonts path, specified in any of the measurements above plus `em` or `rem`

## CSS

prawn-svg supports CSS, both in `<style>` blocks and `style` attributes.

In CSS selectors you can use element names, IDs, classes, attributes (existence, `=`, `^=`, `$=`, `*=`, `~=`, `|=`)
and all combinators (` `, `>`, `+`, `~`).
The pseudo-classes `:first-child`, `:last-child` and `:nth-child(n)` (where n is a number) also work.

Warning: Ruby versions less than 2.6.0 have a bug in the REXML XPath implementation which means under some
conditions the `+` combinator will not pick up all matching elements.  See `stylesheets_spec.rb` for an
explanation if you're stuck on an old version of Ruby.

Pseudo-elements and the other pseudo-classes are not supported.  Specificity ordering is
implemented, but `!important` is not.

## Not supported

prawn-svg does not support hyperlinks, patterns or filters.

It does not support text in the clip area, but you can clip shapes and text by any shape.

## Configuration

### Fonts

By default, prawn-svg has a fonts path of <tt>["/Library/Fonts", "/System/Library/Fonts", "#{ENV["HOME"]}/Library/Fonts", "/usr/share/fonts/truetype"]</tt> to catch
Mac OS X and Debian Linux users.  You can add to the font path:

```ruby
  Prawn::SVG::FontRegistry.font_path << "/my/font/directory"
```

### Using with prawn-rails

In your Gemfile, put `gem 'prawn-svg'` before `gem 'prawn-rails'` so that prawn-rails can see the prawn-svg extension.

## Licence

MIT licence.  Copyright Roger Nesbitt.
