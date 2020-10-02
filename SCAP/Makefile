XSLT		= java -jar ~/saxon/saxon-he-10.1.jar
OSCAP		= ~/Projects/github/OpenSCAP/openscap/build/oscap_wrapper
TIDY		= /usr/bin/tidy

DIR		= ../build/All_rules

all: tidy XCCDF datastream report

inputs:

tidy:
	# de-louse the input
	${TIDY} --show-errors 0 \
		--output-xml true \
		--numeric-entities true \
		--output-encoding utf8 \
		--input-encoding utf8 \
		--logical-emphasis true \
		--drop-proprietary-attributes true \
		--coerce-endtags true \
		-output ${DIR}/all_rules.xhtml \
		${DIR}/all_rules.html || echo untidy

XCCDF:
	# generate the XCCDF document from the input
	$(XSLT) -s:${DIR}/all_rules.xhtml \
		-xsl:html-to-xccdf.xsl \
	       	-o:${DIR}/xccdf.xml \
		SCAP-version=1.3 \
		id-namespace=gov.nist.mscp.content \
		OVAL-URI=${DIR}/All_rules.xml
	# the input OVAL document will be copied to a companion of the XCCDF document named 'oval.xml'
	# a gratuitous OCIL document is provided
	cp ocil.xml ${DIR}

datastream:
	# generate the SCAP data stream collection document
	$(XSLT) -s:${DIR}/xccdf.xml \
		-xsl:xccdf-to-ds.xsl \
		-o:${DIR}/datastream.xml \
		SCAP-version=1.3 \
		id-namespace=gov.nist.mscp.content

report:
	# generate an XCCDF report for quality assurance
	$(XSLT) -s:${DIR}/xccdf.xml \
		-xsl:xccdf-to-html.xsl \
		-o:${DIR}/xccdf.html
