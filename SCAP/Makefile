XSLT		= java -jar ~/saxon/saxon-he-10.1.jar
TIDY		= /usr/bin/tidy
VAL		= java -Djava.protocol.handler.pkgs=sun.net.www.protocol -jar ~/Projects/scapval/scapval-1.3.5.jar

DIR		= ../build/All_rules

all: inputs tidy XCCDF datastream report

inputs:
	# generate the HTML checklist document
	../scripts/generate_guidance.py ../baselines/all_rules.yaml 2>/dev/null
	# generate the related OVAL content
	../scripts/yaml-to-oval.py ../baselines/all_rules.yaml
	# outputs end up in ${DIR}

tidy:
	# de-louse the input HTML
	# DO NOT use the treacherous -indent option
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
		benchmark-id-suffix=macOS_10.15 \
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
		id-namespace=gov.nist.mscp.content \
		datastream-id-suffix=macOS_10.15

report:
	# generate an XCCDF report for quality assurance
	$(XSLT) -s:${DIR}/xccdf.xml \
		-xsl:xccdf-to-html.xsl \
		-o:${DIR}/xccdf.html

validate:
	# validate the datastream using SCAP content validation tool
	( cd ${DIR}; ${VAL} -scapversion 1.3 -online -file datastream.xml >scapval-report.txt )
	# See ${DIR}/validation-report.html for results
