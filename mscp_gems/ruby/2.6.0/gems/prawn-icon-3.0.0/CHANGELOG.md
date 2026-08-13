# 3.0.0 - November 10, 2020

* **breaking change** - Fix incorrect layout and line-wrapping logic for inline-formatted icons. Please see [Inline Format Changes](#inline-format-changes) for more details.
* Add a `#formatted_icon_box` method to retain the previous inline icon behaviour.
* Allow `#formatted_icon_box` to accept absolute positioning parameters (`x`, `y`, and `at`). Thanks @navinspm!
* Update fontawesome from version `5.11.2` to `5.15.1`.
* See FontAwesome's [upgrade guide](https://github.com/FortAwesome/Font-Awesome/blob/57005cea6da7d1c67f3466974aecd25485f60452/UPGRADING.md) for more details.
* Introduce a configuration mechanism so that the font directory can be customized as follows:

```ruby
Prawn::Icon.configure do |config|
  config.font_directory = '/path/to/fonts'
end
```

* Deprecate the global variables of `Prawn::Icon::Base::FONTDIR` and `Prawn::Icon::Compatibility::SHIMS`. Use `Prawn::Icon.configuration.font_directory` and `Prawn::Icon::Compatibility.shims` instead.
* Use `Gem::Specification#full_gem_path` to get the root path of the gem directory to resolve https://github.com/jessedoyle/prawn-icon/issues/45.

#### Inline Format Changes

As noted in https://github.com/jessedoyle/prawn-icon/issues/49, `Prawn::Icon` did not correctly respect page boundaries for inline-formatted icons.

The fix for the issue requires `Prawn::Icon` to use the inline layout and formatting logic implemented in `Prawn`.

This change has ramifications to the `#icon` and `#inline_icon` method return values, but most applications should not require changes.

Changes are listed below:

* `#icon` - returns `nil` with the `inline_format: true` parameter.
* `#inline_icon` - returns `nil` (instead of a `Prawn::Text::Formatted::Box` instance).

You can call `#formatted_icon_box` to retain the previous inline icon functionality.

# 2.5.0 - October 4, 2019

* Update FontAwesome from `5.8.2` to `5.11.2`.
* See FontAwesome's [upgrade guide](https://github.com/FortAwesome/Font-Awesome/blob/master/UPGRADING.md) for more details.

# 2.4.0 - May 26, 2019

* Update FontAwesome from `5.4.0` to `5.8.2`.
* See FontAwesome's [upgrade guide](https://github.com/FortAwesome/Font-Awesome/blob/master/UPGRADING.md) for more details.
* Update the Payment Icon URL to https://paymentfont.com.

# 2.3.0 - October 8, 2018

* Update FontAwesome to version from `5.0.13` to `5.4.0`.
* See FontAwesome's [release page](https://github.com/FortAwesome/Font-Awesome/releases/tag/5.4.0) for more details.

# 2.2.0 - May 20, 2018

* Move out shim configuration into a `.yml` file located inside the `data/fonts/fa4/shims.yml` file.
* Update FontAwesome TTF files and legend files from 5.0.8 to 5.0.13.
* Add additional compatibility shims that were missing for some icons from FontAwesome 4. This version release is now fully backwards-compatible with all icon specifiers present in FontAwesome 4 (via version `1.4.0` of this gem).
* Fix a bug in the FontAwesome converter tool by properly requiring `fileutils` before execution.

# 2.1.0 - April 1, 2018

* Introduce backwards compatibility with FontAwesome 4 icon keys by dynamically
  rewriting all instances of `fa-*` to their appropriate FontAwesome 5 equivalent
  key. This is achieved by implementing a shim generated from the FontAwesome metadata.
* Introduce a deprecation warning written to `STDERR` when any `fa-*` key is
  encountered. The compatibility shim will be removed in the next major version
  of `Prawn::Icon` (`3.0.0`).
* See the [discussion here](https://github.com/jessedoyle/prawn-icon/pull/33) for more details.

# 2.0.0 - March 7, 2018

* [**breaking change**] Update to FontAwesome 5.0.8. FontAwesome 5 now provides 3 different font families: `brands`, `regular` and `solid`. The specifiers for these font icons are now: `fab`, `far` and `fas`.
* [**breaking change**] Remove GitHub Octicons because Octicons are now only [delivered via SVG](https://github.com/blog/2112-delivering-octicons-with-svg).
* [**breaking change**] Make the font specifier a required attribute for `Prawn::Icon::FontData#new`. Previously it was assumed to be `fa`.
* Write a new tool `tool/fontawesome/converter.rb` that accepts the FontAwesome metadata YAML file ([link](https://github.com/FortAwesome/Font-Awesome/blob/31281606f5205b0191c17c3b4d2d56e1ddbb2dc6/advanced-options/metadata/icons.yml)), and generates the correct legend files for `brands`, `regular` and `solid` styles.
* Require 'prawn/icon/version' with by default.

# 1.4.0 - Sept 11, 2017

- Update dependency gems to latest version.
- Fix `rubocop` config to show cop names as well as increase the ABC complexity slightly.
- Add internal tooling to assist with the SCSS => YAML mappings of FontAwesome and PaymentFont.
- Update FontAwesome to `v4.7.0` from `v4.6.3`. See [changelog](http://fontawesome.io/icons#new).
- Update PaymentFont to `v1.2.5` from `v1.1.2`. See [icons](https://paymentfont.com/#icons).
- Update Octicons from to `v4.4.0` from `v3.1.0`. NOTE: As Octicons have moved from font-based icons to SVG after this version, this will be the final octicon version in `prawn/icon`. See the [wiki](https://github.com/blog/2112-delivering-octicons-with-svg).
- Fix rubocop warnings for whitespace.

# 1.3.0 - Oct 15, 2016

- Update rubocop developement dependency (to `0.44.1`).
- Add `simplecov` as a development dependency and require 100% coverage.
- Break out `Prawn::Icon::Interface` into its own file. This resolves issue [#27](https://github.com/jessedoyle/prawn-icon/issues/27).

# 1.2.0 - Sept 12, 2016

- Update FontAwesome from v4.5.0 to v4.6.3. See [changelog](http://fontawesome.io/icons#new).
- Refactor spec files to remove duplication using `let` blocks.
- Break internal dependencies to `Prawn::Icon::Base` to allow selective code requires.
  e.g. (to require only `prawn/icon/font_data`):

  ```ruby
    require 'prawn/icon/base'
    require 'prawn/icon/font_data'
  ```

  This resolves issue [#27](https://github.com/jessedoyle/prawn-icon/issues/27). Thanks @mojavelinux for reporting!
- Introduce `Prawn::Icon::Errors` to contain internal exception classes.
- `Prawn::Icon::FONTDIR` is now an alias to `Prawn::Icon::Base::FONTDIR` for compatibilty.
- Add basic spec files for `Prawn::Icon::Base` and separate exception classes.
- Minor backwards-compatible code refactor of `Prawn::Icon::FontData` for readability.
- Add a spec to test inline_icon with final_gap: false to achieve 100% coverage.

# 1.1.1 - Jun 24, 2016

- BUGFIX: Inline icons now properly render at the correct cursor position with the correct line gap and box leading[#24](https://github.com/jessedoyle/prawn-icon/issues/24). Thanks @ToniTornado for reporting!

# 1.1.0 - March 16, 2016

- Update FontAwesome from v4.4.0 to v4.5.0. See [changelog](http://fontawesome.io/icons#new).
- Refactor specs to use `expect(foo).to be true` over `expect(foo).to be_true`.
- Update development dependencies to latest.

# 1.0.0 - September 9, 2015

- *(breaking change)* Updated Octicons from v2.4.1 to v3.1.0.
- The following icons were removed:
  - `octicon-microsope`
  - `octicon-beer`
  - `octicon-split`
  - `octicon-puzzle`
  - `octicon-steps`
  - `octicon-podium`
  - `octicon-timer`
  - `octicon-hourglass`
  - all `octicon-alignment` icons
  - all `octicon-move` icons
  - all `octicon-playback` icons
  - all `octicon-jump` icons
- The following icons were added:
  - `octicon-beaker`
  - `octicon-bell`
  - `octicon-desktop-download`
  - `octicon-watch`
  - `octicon-shield`
- Updated FontAwesome from v4.3.0 to v4.4.0. See [changelog](http://fontawesome.io/icons#new).

# 0.7.1 - August 4, 2015

- Moved the internal font directory from `fonts` to `data/fonts` for consistency between Prawn-related gems [#16](https://github.com/jessedoyle/prawn-icon/issues/16).

# 0.7.0 - July 23, 2015

- Update Travis config to relax the versions of `Prawn` and `Ruby` that are tested against. See `.travis.yml` to see what versions are supported (though you shouldn't have issues with other versions).
- Implement inline_format for table icons. [#14](https://github.com/jessedoyle/prawn-icon/pull/14).
- Updated Octicons to v2.4.1. See [changelog](https://github.com/github/octicons/releases/) between versions 2.1.2 and 2.4.1.

# 0.6.4 - May 4, 2015

- [PaymentFont](https://paymentfont.com) is now supported and included in `Prawn::Icon`.

# 0.6.3 - March 4, 2015

- Relaxed Prawn runtime dependency from >= 1.3.0 to >= 1.1.0.
- Added CI tests for multiple versions of Prawn.
- Added missing `end` statement to example code in README.

# 0.6.2 - February 10, 2015

- Added this CHANGELOG.
- Added the `table_icon` method to simplify icon use in conjuction with `Prawn::Table`.
- Added a `.yardopts` file for better documentation.
- Clean `.gemspec` to increase readability.

# 0.6.1 - January 27, 2015

- Upgraded FontAwesome to `v4.3.0`.

# 0.6.0 - January 20, 2015

- Single-quoted attributes are now supported when using `inline_format: true`.
- Prawn is now specified as a runtime dependency of `prawn/icon`.

# 0.5.1 - November 2, 2014

- Bugfix for improperly cached font data.
- Added Codeclimate and Travis CI.

# 0.5.0 - October 29, 2014

- Initial public release.
