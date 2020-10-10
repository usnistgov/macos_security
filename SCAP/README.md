# SCAP Content Generation

Generation of SCAP content uses XSLT to create an XCCDF document with an accompanying OVAL document, bundled into an SCAP data stream collection document.

Steps:

- Generate the "all rules" variant of the checklist in HTML form.
- Generate the "all rules" variant of the checklist in OVAL form.
- Generate the XCCDF document using the "all rules" checklist and OVAL as inputs.
- Generate the SCAP data stream document using the XCCDF and OVAL documents.
- Generate a report from the XCCDF document to be used for quality checking.

These steps are configured within the Makefile.

## Dependencies

The supplied Makefile relies on the following components:
- HTML Tidy — [Tidy](http://www.html-tidy.org/) is an HTML/XML syntax checker and reformatter http://www.html-tidy.org/

- Saxon 10 — [Saxon](https://www.saxonica.com/products/products.xml) is an [XSLT 3.0](https://www.w3.org/TR/xslt-30/) implementation. 
The [HE](https://www.saxonica.com/products/PD10/HE.pdf) variant, which is open source, will suffice for the XSL transformations.

- SCAP Content Validation Tool — See 
[SCAP Content Validation Tool](https://csrc.nist.gov/projects/security-content-automation-protocol/scap-releases/scap-1-3)
under "Tools".
Version 1.3.5 or later is required.


