# SCAP Content Generation

Generation of SCAP content uses XSLT to create an XCCDF document with an accompanying OVAL document, bundled into an SCAP data stream collection document.

Steps:

- Generate the "all rules" variant of the checklist in HTML form.
- Generate the "all rules" variant of the checklist in OVAL form.
- Generate the XCCDF document using the "all rules" checklist and OVAL as inputs.
- Generate the SCAP data stream document using the XCCDF and OVAL documents.
- Generate a report from the XCCDF document to be used for quality checking.

## Dependencies

The supplied Makefile relies on the following components:
- HTML Tidy — [Tidy](http://www.html-tidy.org/) is an HTML/XML syntax checker and reformatter http://www.html-tidy.org/

- Saxon 10 — [Saxon](https://www.saxonica.com/products/products.xml) is an [XSLT 3.0](https://www.w3.org/TR/xslt-30/) implementation. 
The [HE](https://www.saxonica.com/products/PD10/HE.pdf) variant, which is open source, will suffice for the XSL transformations.

## Optional utilities

- NIST SCAP 1.3 Content Validation Tool (available [here](https://csrc.nist.gov/Projects/Security-Content-Automation-Protocol/SCAP-Releases/scap-1-3)).
- OpenSCAP (available [here](https://github.com/OpenSCAP/openscap)).

