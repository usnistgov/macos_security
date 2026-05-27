<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="config/default/images/mscp_readme_banner_dark.png">
    <source media="(prefers-color-scheme: light)" srcset="config/default/images/mscp_readme_banner.png">
    <img src="config/default/images/mscp_readme_banner.png" alt="macOS Security Compliance" width="550">
  </picture>
</p>

<p align="center">
  <a href="https://www.apple.com/macos/"><img src="https://badgen.net/badge/icon/apple?icon=apple&label" alt="Apple"></a>
  <a href="https://www.apple.com/macos/"><img src="https://badgen.net/badge/icon/26.0?icon=apple&label" alt="macOS 26.0"></a>
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

mSCP is the technical implementation of NIST SP 800-219 (Rev. 2), [_Automated Secure Configuration Guidance from the macOS Security Compliance Project_](https://csrc.nist.gov/pubs/sp/800/219/r2/final) — the official NIST guidance for automated secure configuration of macOS. Apple also acknowledges the project on its [Platform Certifications](https://support.apple.com/guide/certifications/macos-security-compliance-project-apc322685bb2/web) page.

To learn more, visit the [project website](http://pages.nist.gov/macos_security/). If you would like to contribute, see the [contributor guidance](CONTRIBUTING.md).

## Supported Frameworks

- NIST SP 800-53 <a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/red?icon=apple&label" alt="macOS"></a><a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a><a href="https://www.apple.com/os/visionos/"><img src="https://badgen.net/badge/icon/visionOS/green?icon=apple&label" alt="visionOS"></a>
- NIST SP 800-171r3 <a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/red?icon=apple&label" alt="macOS"></a><a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a><a href="https://www.apple.com/os/visionos/"><img src="https://badgen.net/badge/icon/visionOS/green?icon=apple&label" alt="visionOS"></a>
- NIST SP 800-171r2 (CMMC) <a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/red?icon=apple&label" alt="macOS"></a><a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a><a href="https://www.apple.com/os/visionos/"><img src="https://badgen.net/badge/icon/visionOS/green?icon=apple&label" alt="visionOS"></a>
- CIS Benchmarks (Level 1 & 2) <a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/red?icon=apple&label" alt="macOS"></a><a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a><a href="https://www.apple.com/os/visionos/"><img src="https://badgen.net/badge/icon/visionOS/green?icon=apple&label" alt="visionOS"></a>
- CIS Controls (v8) <a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/red?icon=apple&label" alt="macOS"></a><a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a><a href="https://www.apple.com/os/visionos/"><img src="https://badgen.net/badge/icon/visionOS/green?icon=apple&label" alt="visionOS"></a>
- CNSSI 1253 <a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/red?icon=apple&label" alt="macOS"></a><a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a><a href="https://www.apple.com/os/visionos/"><img src="https://badgen.net/badge/icon/visionOS/green?icon=apple&label" alt="visionOS"></a>
- DISA STIG <a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/red?icon=apple&label" alt="macOS"></a><a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a><a href="https://www.apple.com/os/visionos/"><img src="https://badgen.net/badge/icon/visionOS/green?icon=apple&label" alt="visionOS"></a>
- BSI Indigo <a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a><a href="https://www.apple.com/os/visionos/"><img src="https://badgen.net/badge/icon/visionOS/green?icon=apple&label" alt="visionOS"></a>
- NLMAPGOV (Base and Plus) <a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS?icon=apple&label" alt="macOS"></a><a href="https://www.apple.com/os/ios/"><img src="https://badgen.net/badge/icon/iOS & iPadOS?icon=apple&label" alt="iOS & iPadOS"></a>
- HICP — Health Industry Cybersecurity Practices (Large Organizations) <a href="https://www.apple.com/os/macos/"><img src="https://badgen.net/badge/icon/macOS/red?icon=apple&label" alt="macOS"></a>

Don't see your framework listed? Reach out through the [contributor guidance](CONTRIBUTING.md) or the [project website](http://pages.nist.gov/macos_security/) to find out how we can get it included.

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

Refer to the [CHANGELOG](CHANGELOG.md) for a complete list of changes.

## NIST Disclaimer

Any identification of commercial or open-source software in this document is done so purely in order to specify the methodology adequately. Such identification is not intended to imply recommendation or endorsement by the National Institute of Standards and Technology, nor is it intended to imply that the software identified are necessarily the best available for the purpose.
