XSLT		= /usr/local/bin/saxon
TIDY		= /usr/local/bin/tidy
VAL		= java -Djava.protocol.handler.pkgs=sun.net.www.protocol -jar ~/Projects/scapval/scapval-1.3.5.jar

DIR		= ../build/All_rules
VERSION	= $(shell ./version.sh)
OS = $(shell ./os.sh)

all: inputs tidy XCCDF datastream report beautify

inputs:
	# generate the HTML checklist document
	../scripts/generate_guidance.py -g ../baselines/all_rules.yaml 2>/dev/null
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
		id-namespace=content.mscp.nist.gov \
		benchmark-id-suffix=macOS_11.0 \
		OVAL-URI=${DIR}/All_rules.xml \
		include-CPE=1
	# the input OVAL document will be copied to a companion of the XCCDF document named 'oval.xml'
	# a gratuitous OCIL document is provided
	/bin/cp ocil.xml                 ${DIR}
	/bin/cp macos-cpe-dictionary.xml ${DIR}
	/bin/cp macos-cpe-oval.xml       ${DIR}

datastream:
	# generate the SCAP data stream collection document
	$(XSLT) -s:${DIR}/xccdf.xml \
		-xsl:xccdf-to-ds.xsl \
		-o:${DIR}/datastream.xml \
		SCAP-version=1.3 \
		id-namespace=content.mscp.nist.gov \
		datastream-id-suffix=macOS_11.0 \
		include-CPE=1

report:
	# generate an XCCDF report for quality assurance
	$(XSLT) -s:${DIR}/xccdf.xml \
		-xsl:xccdf-to-html.xsl \
		-o:${DIR}/xccdf.html

beautify:


	/usr/bin/xmllint ${DIR}/datastream.xml --format --output "${DIR}/macOS_${OS}_Security_Compliance_Benchmark-Rev${VERSION}.xml"

validate:
	# validate the datastream using SCAP content validation tool
	( cd ${DIR}; ${VAL} -scapversion 1.3 -online -file datastream.xml >scapval-report.txt )
	# See ${DIR}/validation-report.html for results
