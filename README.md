<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="src/mscp/data/images/mscp_readme_banner_dark.png">
    <source media="(prefers-color-scheme: light)" srcset="src/mscp/data/images/mscp_readme_banner.png">
    <img src="src/mscp/data/images/mscp_readme_banner.png" alt="macOS Security Compliance" width="550">
  </picture>
</p>

<p align="center">
  <a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/apple?icon=apple&label" alt="Apple"></a>
  <a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/26.0?icon=apple&label" alt="macOS 26.0"></a>
  <a href="http://pages.nist.gov/macos_security/"><img src="https://badgen.net/badge/website/pages.nist.gov/blue" alt="Website"></a>
  <a href="LICENSE.md"><img src="https://badgen.net/badge/license/CC%20BY%204.0/green" alt="License"></a>
  <a href="https://github.com/usnistgov/macos_security/stargazers"><img src="https://badgen.net/github/stars/usnistgov/macos_security" alt="Stars"></a>
</p>

**Supported platforms:** macOS, iOS/iPadOS, and visionOS.

The macOS Security Compliance Project (mSCP) is an [open-source](LICENSE.md) project that helps organizations secure their Apple devices. You choose the security rules to enforce, and mSCP generates everything you need:

- **Configuration profiles** to apply the rules
- **Declarative Device Management (DDM)** assets for device management solutions that support declarative delivery
- **Documentation** to explain the setup
- **Compliance scripts** to verify and enforce rules that profiles cannot

Beyond the built-in frameworks, organizations can build customized baselines to meet their specific cybersecurity needs. Vendors can also use mSCP as a source to build manifests, datapoints, and other compliance content for their products.

The security rules are derived from NIST Special Publication (SP) 800-53, _Security and Privacy Controls for Information Systems and Organizations_, Revision 5. mSCP is a joint project of federal IT security staff from the National Institute of Standards and Technology (NIST), the National Aeronautics and Space Administration (NASA), the Defense Information Systems Agency (DISA), and Los Alamos National Laboratory (LANL), along with a community of contributors who test the project and provide feedback to keep it on the cutting edge of Apple platform security.

mSCP is the technical implementation of NIST SP 800-219 (Rev. 2), [_Automated Secure Configuration Guidance from the macOS Security Compliance Project_](https://csrc.nist.gov/pubs/sp/800/219/r2/final) — the official NIST guidance for automated secure configuration of macOS. Apple also acknowledges the project on its Apple Platform Certifications for [macOS](https://support.apple.com/guide/certifications/macos-security-compliance-project-apc322685bb2/web) & [iOS/iPadOS](https://support.apple.com/guide/certifications/ios-and-ipados-security-compliance-project-apcb2892d3b0/web) pages.

To learn more, visit the [project website](http://pages.nist.gov/macos_security/). If you would like to contribute, see the [contributor guidance](CONTRIBUTING.adoc).

## Supported Frameworks

|Country of Origin|Framework Name|OS Supported|
|--------------------|---------------------|--------------------------|
|<a href="https://nist.gov"><img src="https://badgen.net/badge/US/Origin?icon=https%3A%2F%2Fraw.githubusercontent.com%2Flipis%2Fflag-icons%2F086f7e97d657358203916dbe84f61c2bccaa81eb%2Fflags%2F1x1%2Fus.svg" alt="NIST"></a>|NIST SP 800-53|<a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/green?icon=apple&label" alt="macOS"></a><a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a><a href="https://www.apple.com/os/visionos/"><img src="https://badgen.net/badge/icon/visionOS/red?icon=apple&label" alt="visionOS"></a>|
|<a href="https://nist.gov"><img src="https://badgen.net/badge/US/Origin?icon=https%3A%2F%2Fraw.githubusercontent.com%2Flipis%2Fflag-icons%2F086f7e97d657358203916dbe84f61c2bccaa81eb%2Fflags%2F1x1%2Fus.svg" alt="NIST"></a>|NIST SP 800-171r3|<a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/green?icon=apple&label" alt="macOS"></a><a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a><a href="https://www.apple.com/os/visionos/"><img src="https://badgen.net/badge/icon/visionOS/red?icon=apple&label" alt="visionOS"></a>|
|<a href="https://nist.gov"><img src="https://badgen.net/badge/US/Origin?icon=https%3A%2F%2Fraw.githubusercontent.com%2Flipis%2Fflag-icons%2F086f7e97d657358203916dbe84f61c2bccaa81eb%2Fflags%2F1x1%2Fus.svg" alt="NIST"></a>|NIST SP 800-171r2 (CMMC)|<a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/green?icon=apple&label" alt="macOS"></a><a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a><a href="https://www.apple.com/os/visionos/"><img src="https://badgen.net/badge/icon/visionOS/red?icon=apple&label" alt="visionOS"></a>|
|<a href="https://cisecurity.org"><img src="https://badgen.net/badge/US/Origin?icon=https%3A%2F%2Fraw.githubusercontent.com%2Flipis%2Fflag-icons%2F086f7e97d657358203916dbe84f61c2bccaa81eb%2Fflags%2F1x1%2Fus.svg" alt="NIST"></a>|CIS Benchmarks (Level 1 & 2)|<a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/green?icon=apple&label" alt="macOS"></a><a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a>|
|<a href="https://cisecurity.org"><img src="https://badgen.net/badge/US/Origin?icon=https%3A%2F%2Fraw.githubusercontent.com%2Flipis%2Fflag-icons%2F086f7e97d657358203916dbe84f61c2bccaa81eb%2Fflags%2F1x1%2Fus.svg" alt="NIST"></a>|CIS Controls (v8)|<a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/green?icon=apple&label" alt="macOS"></a><a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a><a href="https://www.apple.com/os/visionos/"><img src="https://badgen.net/badge/icon/visionOS/red?icon=apple&label" alt="visionOS"></a>|
|<a href="https://nist.gov"><img src="https://badgen.net/badge/US/Origin?icon=https%3A%2F%2Fraw.githubusercontent.com%2Flipis%2Fflag-icons%2F086f7e97d657358203916dbe84f61c2bccaa81eb%2Fflags%2F1x1%2Fus.svg" alt="NIST"></a>|CNSSI 1253|<a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/green?icon=apple&label" alt="macOS"></a><a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a><a href="https://www.apple.com/os/visionos/"><img src="https://badgen.net/badge/icon/visionOS/red?icon=apple&label" alt="visionOS"></a>|
|<a href="https://disa.mil"><img src="https://badgen.net/badge/US/Origin?icon=https%3A%2F%2Fraw.githubusercontent.com%2Flipis%2Fflag-icons%2F086f7e97d657358203916dbe84f61c2bccaa81eb%2Fflags%2F1x1%2Fus.svg" alt="DISA"></a>|DISA STIG|<a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/green?icon=apple&label" alt="macOS"></a><a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a><a href="https://www.apple.com/os/visionos/"><img src="https://badgen.net/badge/icon/visionOS/red?icon=apple&label" alt="visionOS"></a>|
|<a href="https://www.bsi.bund.de/"><img src="https://badgen.net/badge/Germany/Origin?icon=https://raw.githubusercontent.com/lipis/flag-icons/refs/heads/main/flags/1x1/de.svg" alt="BSI"></a>|BSI Indigo|<a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a></a>|
|<a href="https://www.bio-overheid.nl"><img src="https://badgen.net/badge/Netherlands/Origin?icon=https://raw.githubusercontent.com/lipis/flag-icons/086f7e97d657358203916dbe84f61c2bccaa81eb/flags/1x1/nl.svg" alt="BIO"></a>|NLMAPGOV (Base and Plus)|<a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/green?icon=apple&label" alt="macOS"></a><a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a>|
|<a href="https://405d.hhs.gov"><img src="https://badgen.net/badge/US/Origin?icon=https%3A%2F%2Fraw.githubusercontent.com%2Flipis%2Fflag-icons%2F086f7e97d657358203916dbe84f61c2bccaa81eb%2Fflags%2F1x1%2Fus.svg" alt="HHS"></a>|HICP — Health Industry Cybersecurity Practices (Large Organizations)|<a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/green?icon=apple&label" alt="macOS"></a>|

Don't see your framework listed? Reach out through the [contributor guidance](CONTRIBUTING.adoc) or the [project website](http://pages.nist.gov/macos_security/) to find out how we can get it included.

## Usage

Civilian agencies are to use the National Checklist Program as required by [NIST 800-70](https://csrc.nist.gov/publications/detail/sp/800-70/rev-4/final).

> [!NOTE]
> Part 39 of the Federal Acquisition Regulations, section 39.101 paragraph (c) states, “In acquiring information technology, agencies shall include the appropriate information technology security policies and requirements, including use of common security configurations available from the National Institute of Standards and Technology’s website at https://checklists.nist.gov. Agency contracting officers should consult with the requiring official to ensure the appropriate standards are incorporated.”

## Authors

| Name | Organization |
|------|--------------|
| Bob Gendler | NIST |
| Allen Golbig | Jamf |
| Dan Brodjieski | NASA |
| John Mahlman IV | Leidos |
| Aaron Kegerreis | DISA |
| Cody Keats | Coursera |
| Henry Stamerjohann | Declarative IT GmbH |
| Marco A Piñeyro II | State Department |
| Jason Blake | NIST |
| Blair Heiserman | NIST |
| Joshua Glemza | NASA |
| Elyse Anderson | NASA |
| Gary Gapinski | NASA |

## Changelog

Refer to the [CHANGELOG](CHANGELOG.adoc) for a complete list of changes.

## NIST Disclaimer

Any identification of commercial or open-source software in this document is done so purely in order to specify the methodology adequately. Such identification is not intended to imply recommendation or endorsement by the National Institute of Standards and Technology, nor is it intended to imply that the software identified are necessarily the best available for the purpose.
