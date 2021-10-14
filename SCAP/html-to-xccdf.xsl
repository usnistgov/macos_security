<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" exclude-result-prefixes="xs xccdf" version="3.0"
    xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" xmlns:xhtml="http://www.w3.org/1999/xhtml" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:fn="local-function" xpath-default-namespace="">
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl" scope="stylesheet">
        <xd:desc>
            <xd:p><xd:b>Created on:</xd:b> Jun 8, 2020</xd:p>
            <xd:p><xd:b>Author:</xd:b> gapinski</xd:p>
            <xd:p>See https://csrc.nist.gov/publications/detail/sp/800-126/rev-3/final 6.2.3§</xd:p>
            <xd:p/>
        </xd:desc>
    </xd:doc>
    <!-- "namespace" for identifiers -->
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p>"namespace" for identifiers</xd:p>
            <xd:p>See <xd:a href="https://csrc.nist.gov/publications/detail/nistir/7275/rev-4/final">NISTIR 7275r4 §6.2.3</xd:a> for an explanation of this value</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:param name="id-namespace" as="xs:string" required="no" select="'content.scap.example.com'" static="true"/>
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p>"namespace" reversed</xd:p>
            <xd:p>See <xd:a href="https://csrc.nist.gov/publications/detail/nistir/7275/rev-4/final">NISTIR 7275r4 §6.2.3</xd:a> for an explanation of this value</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:variable name="xccdf-namespace" as="xs:string" select="string-join(reverse(tokenize($id-namespace, '\.')), '.')"/>
    <!-- (unique) suffix for <Benchmark> @id -->
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p>Element Identifier suffix ("name")</xd:p>
            <xd:p>See <xd:a href="https://csrc.nist.gov/publications/detail/nistir/7275/rev-4/final">NISTIR 7275r4 §6.2.3</xd:a> for an explanation of this value</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:param name="benchmark-id-suffix" as="xs:string" required="true"/>
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl" scope="stylesheet">
        <xd:desc>
            <xd:p><xd:b>Created on:</xd:b> Jun 8, 2020</xd:p>
            <xd:p><xd:b>Author:</xd:b> gapinski</xd:p>
            <xd:p/>
        </xd:desc>
    </xd:doc>
    <!-- target SCAP version -->
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p>target SCAP version</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:param name="SCAP-version" as="xs:decimal" required="no" select="1.3"/>
    <!-- include CPE stuff -->
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p>include CPE stuff</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:param name="include-CPE" as="xs:boolean" required="false" select="true()"/>
    <!-- include "all-rule" profile -->
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p>manufacture "all-rule" profile</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:param name="include-all-rule-profile" as="xs:boolean" required="false" select="false()"/>
    <!-- Gratuitous references to SCAP standards are not included by default -->
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p>Gratuitous references to SCAP standards may be included</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:param name="include-scap-references" as="xs:boolean" required="no" select="false()"/>
    <!-- Indent output document -->
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p>Indent output document</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:param name="indent-output" as="xs:boolean" required="no" select="false()" static="true"/>
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p>Origin of related OVAL definitions</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:param name="OVAL-URI" as="xs:string" required="true"/>
    <xsl:variable name="OVAL-document" as="document-node()" select="doc(resolve-uri($OVAL-URI))"/>
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p>UTC offset</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:variable name="UTC" as="xs:duration" select="xs:dayTimeDuration('PT0H')"/>
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p>UTC date</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:variable name="UTC-date" select="adjust-date-to-timezone(current-date(), $UTC)"/>
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p>UTC dateTime</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:variable name="UTC-datetime" select="adjust-dateTime-to-timezone(current-dateTime(), $UTC)"/>
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p>Strip numeric prefix from titles</xd:p>
        </xd:desc>
        <xd:param name="title"/>
        <xd:return/>
    </xd:doc>
    <xsl:function name="fn:retitle" as="xs:string">
        <xsl:param name="title" as="xs:string"/>
        <xsl:value-of select="replace($title, '^\s*[0123456789.]+\s+', '')"/>
    </xsl:function>
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl" scope="stylesheet">
        <xd:desc>
            <xd:p><xd:b>Created on:</xd:b> Jun 8, 2020</xd:p>
            <xd:p><xd:b>Author:</xd:b> gapinski</xd:p>
            <xd:p>Transform HTML-ized benchmark to XCCDF</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:strip-space elements="*"/>
    <xsl:preserve-space elements="pre"/>
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p/>
        </xd:desc>
    </xd:doc>
    <xsl:output method="xml"/>
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p>New line character</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:variable name="LF" as="xs:string" select="'&#x0a;'"/>
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p>Default output mode</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:output use-when="$indent-output" indent="true"/>
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl">
        <xd:desc>
            <xd:p>Create the XCCDF document</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:template match="/">
        <!--<xsl:message expand-text="true">OVAL input: {resolve-uri($OVAL-URI)}</xsl:message>-->
        <!--<xsl:message expand-text="true">OVAL output: {resolve-uri('oval.xml', current-output-uri())}</xsl:message>-->
        <xsl:result-document href="{resolve-uri('oval.xml', current-output-uri())}">
            <xsl:copy-of select="$OVAL-document"/>
        </xsl:result-document>
        <!--<xsl:message expand-text="true">OVAL URI: {$OVAL-URI}</xsl:message>-->
        <!--<xsl:message expand-text="true" xpath-default-namespace="http://oval.mitre.org/XMLSchema/oval-definitions-5">{$OVAL-URI} contains {count($OVAL-document//definition)} definitions</xsl:message>-->
        <!--<xsl:message expand-text="true" xpath-default-namespace="http://oval.mitre.org/XMLSchema/oval-definitions-5">{$OVAL-URI} contains {count($OVAL-document//node())} nodes</xsl:message>-->
        <xsl:copy-of select="$LF"/>
        <xsl:copy-of select="$LF"/>
        <xsl:comment expand-text="true"> This is an SCAP {$SCAP-version} XCCDF document </xsl:comment>
        <xsl:copy-of select="$LF"/>
        <xsl:comment expand-text="true"> Created {$UTC-datetime} </xsl:comment>
        <xsl:copy-of select="$LF"/>
        <xsl:comment expand-text="true"> using {static-base-uri()} </xsl:comment>
        <xsl:copy-of select="$LF"/>
        <xsl:comment expand-text="true"> with {resolve-uri(base-uri())} as input </xsl:comment>
        <xsl:copy-of select="$LF"/>
        <xsl:comment expand-text="true"> and {resolve-uri($OVAL-URI)} as OVAL input </xsl:comment>
        <xsl:copy-of select="$LF"/>
        <xsl:comment expand-text="true"> The SCAP identifier "namespace" chosen for this XCCDF document is «{$xccdf-namespace}» («{$id-namespace}» reversed) </xsl:comment>
        <xsl:copy-of select="$LF"/>
        <xsl:copy-of select="$LF"/>
        <xsl:comment> See https://www.w3.org/TR/xml-model/ for an explanation of the following processing instructions </xsl:comment>
        <xsl:copy-of select="$LF"/>
        <!-- See https://www.w3.org/TR/xml-model/ for an explanation of the following processing instruction -->
        <xsl:processing-instruction name="xml-model">
            <xsl:text>href="https://csrc.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd"</xsl:text>
            <xsl:text> </xsl:text>
            <xsl:text>schematypens="http://www.w3.org/2001/XMLSchema"</xsl:text>
            <xsl:text> </xsl:text>
            <xsl:text>title="XCCDF XML schema"</xsl:text>
        </xsl:processing-instruction>
        <xsl:copy-of select="$LF"/>
        <!-- See https://www.w3.org/TR/xml-model/ for an explanation of the following processing instruction -->
        <xsl:processing-instruction name="xml-model">
            <xsl:text>href="https://csrc.nist.gov/schema/xccdf/1.2/xccdf_1.2.sch"</xsl:text> 
            <xsl:text> </xsl:text>
            <xsl:text>schematypens="http://purl.oclc.org/dsdl/schematron" phase="Benchmark"</xsl:text>
            <xsl:text> </xsl:text>
            <xsl:text>title="XCCDF Schematron schema"</xsl:text>
        </xsl:processing-instruction>
        <xsl:copy-of select="$LF"/>
        <!-- See https://www.w3.org/TR/xml-stylesheet/ for stylesheet association -->
        <!--<xsl:processing-instruction name="xml-stylesheet">
            <xsl:text>href="xccdf-to-html.xsl"</xsl:text>
        </xsl:processing-instruction>-->
        <xsl:copy-of select="$LF"/>
        <xsl:element name="Benchmark" namespace="http://checklists.nist.gov/xccdf/1.2">
            <xsl:attribute name="id" expand-text="true">xccdf_{$xccdf-namespace}_benchmark_{$benchmark-id-suffix}</xsl:attribute>
            <xsl:attribute name="style" expand-text="true">SCAP_{$SCAP-version}</xsl:attribute>
            <xsl:attribute name="resolved" select="true()"/>
            <xsl:attribute name="xml:lang" select="'en'"/>
            <xsl:element name="status" namespace="http://checklists.nist.gov/xccdf/1.2">
                <xsl:attribute name="date" select="$UTC-date"/>
                <!--<xsl:text>incomplete</xsl:text>-->
                <xsl:text>draft</xsl:text>
            </xsl:element>
            <!--<xsl:element name="dc-status" namespace="http://checklists.nist.gov/xccdf/1.2"/>-->
            <xsl:element name="title" namespace="http://checklists.nist.gov/xccdf/1.2">
                <xsl:value-of select="replace(/html/head/title, '\s-.*$', '')"/>
                <!-- see also //div[@class='doctitle'] -->
            </xsl:element>
            <xsl:element name="description" namespace="http://checklists.nist.gov/xccdf/1.2">
                <xsl:element name="div" namespace="http://www.w3.org/1999/xhtml">
                    <xsl:value-of select="replace(/html/head/title, '\s-.*$', '')"/>
                </xsl:element>
            </xsl:element>
            <!--<xsl:element name="notice" namespace="http://checklists.nist.gov/xccdf/1.2">
                <xsl:element name="div" namespace="http://www.w3.org/1999/xhtml">
                    <xsl:element name="p" namespace="http://www.w3.org/1999/xhtml">
                        <xsl:text>FIXME: what (if anything) should appear in the &lt;notice&gt; element? This is typically the location of legal disclaimers.</xsl:text>
                    </xsl:element>
                    <xsl:element name="p" namespace="http://www.w3.org/1999/xhtml">
                        <xsl:text>Example: Do not attempt to implement any of the settings in this guide without first testing them in a non-operational environment. The creators of this guidance assume no responsibility whatsoever for its use by other parties, and makes no guarantees, expressed or implied, about its quality, reliability, or any other characteristic.</xsl:text>
                    </xsl:element>
                </xsl:element>
            </xsl:element>-->
            <xsl:element name="front-matter" namespace="http://checklists.nist.gov/xccdf/1.2">
                <xsl:if test="false()">
                    <xsl:element name="div" namespace="http://www.w3.org/1999/xhtml">
                        <xsl:element name="img" namespace="http://www.w3.org/1999/xhtml">
                            <xsl:copy-of select="/html/body[1]/div[2]/div[1]/div[1]/table[1]/tbody[1]/tr[1]/td[1]/p[1]/strong[1]/span[1]/img[1]/attribute::node()"/>
                        </xsl:element>
                    </xsl:element>
                </xsl:if>
                <xsl:element name="div" namespace="http://www.w3.org/1999/xhtml">
                    <xsl:element name="h2" namespace="http://www.w3.org/1999/xhtml">&lt;front-matter&gt;</xsl:element>
                    <xsl:element name="h3" namespace="http://www.w3.org/1999/xhtml">Foreword</xsl:element>
                    <xsl:apply-templates mode="html" select="//div[@class = 'sect1'][h2/@id = '_foreword']"/>
                </xsl:element>
            </xsl:element>
            <xsl:element name="rear-matter" namespace="http://checklists.nist.gov/xccdf/1.2">
                <xsl:element name="div" namespace="http://www.w3.org/1999/xhtml">
                    <xsl:element name="h2" namespace="http://www.w3.org/1999/xhtml">&lt;rear-matter&gt;</xsl:element>
                    <xsl:element name="h3" namespace="http://www.w3.org/1999/xhtml">Authors</xsl:element>
                    <xsl:element name="p" namespace="http://www.w3.org/1999/xhtml">Please refer to Dublin Core metadata.</xsl:element>
                    <xsl:element name="h3" namespace="http://www.w3.org/1999/xhtml">Acronyms and Definitions</xsl:element>
                    <xsl:element name="dl" namespace="http://www.w3.org/1999/xhtml">
                        <xsl:for-each select="//div[@class = 'sect1'][h2/@id = '_acronyms_and_definitions']//tbody/tr">
                            <xsl:element name="dt" namespace="http://www.w3.org/1999/xhtml">
                                <xsl:value-of select="td[1]/p"/>
                            </xsl:element>
                            <xsl:element name="dd" namespace="http://www.w3.org/1999/xhtml">
                                <xsl:value-of select="td[2]/p"/>
                            </xsl:element>
                        </xsl:for-each>
                    </xsl:element>
                    <xsl:element name="h3" namespace="http://www.w3.org/1999/xhtml">Applicable Documents</xsl:element>
                    <xsl:element name="p" namespace="http://www.w3.org/1999/xhtml">Please refer to XCCDF Benchmark references (i.e., ones which are children of the &lt;Benchmark&gt;
                        element).</xsl:element>
                </xsl:element>
            </xsl:element>
            <xsl:if test="$include-scap-references">
                <xsl:element name="reference" namespace="http://checklists.nist.gov/xccdf/1.2">
                    <xsl:attribute name="href">https://csrc.nist.gov/publications/detail/nistir/7275/rev-4/final</xsl:attribute>
                    <xsl:element name="title" namespace="http://purl.org/dc/elements/1.1/">
                        <xsl:text>Specification for the Extensible Configuration Checklist Description Format (XCCDF) Version 1.2</xsl:text>
                    </xsl:element>
                    <xsl:element name="publisher" namespace="http://purl.org/dc/elements/1.1/">
                        <xsl:text>National Institute of Standards and Technology</xsl:text>
                    </xsl:element>
                </xsl:element>
            </xsl:if>
            <xsl:choose>
                <xsl:when test="$SCAP-version = 1.3">
                    <xsl:element name="reference" namespace="http://checklists.nist.gov/xccdf/1.2">
                        <xsl:attribute name="href">https://csrc.nist.gov/projects/security-content-automation-protocol/scap-releases/scap-1-3</xsl:attribute>
                        <xsl:element name="title" namespace="http://purl.org/dc/elements/1.1/">
                            <xsl:text>Security Content Automation Protocol</xsl:text>
                        </xsl:element>
                        <xsl:element name="publisher" namespace="http://purl.org/dc/elements/1.1/">
                            <xsl:text>National Institute of Standards and Technology</xsl:text>
                        </xsl:element>
                    </xsl:element>
                </xsl:when>
                <xsl:when test="$SCAP-version = 1.2">
                    <xsl:element name="reference" namespace="http://checklists.nist.gov/xccdf/1.2">
                        <xsl:attribute name="href">https://csrc.nist.gov/projects/security-content-automation-protocol/scap-releases/scap-1-2</xsl:attribute>
                        <xsl:element name="title" namespace="http://purl.org/dc/elements/1.1/">
                            <xsl:text>Security Content Automation Protocol</xsl:text>
                        </xsl:element>
                        <xsl:element name="publisher" namespace="http://purl.org/dc/elements/1.1/">
                            <xsl:text>National Institute of Standards and Technology</xsl:text>
                        </xsl:element>
                    </xsl:element>
                </xsl:when>
            </xsl:choose>
            <xsl:if test="$include-CPE">
                <xsl:element name="reference" namespace="http://checklists.nist.gov/xccdf/1.2">
                    <xsl:attribute name="href">macos-cpe-dictionary.xml</xsl:attribute>
                    <xsl:text>platform-cpe-dictionary</xsl:text>
                </xsl:element>
                <xsl:element name="reference" namespace="http://checklists.nist.gov/xccdf/1.2">
                    <xsl:attribute name="href">macos-cpe-oval.xml</xsl:attribute>
                    <xsl:text>platform-cpe-oval</xsl:text>
                </xsl:element>
                <!-- See NIST IR7215 §6.2.5 ¶3-->
                <xsl:element name="platform" namespace="http://checklists.nist.gov/xccdf/1.2">
                    <xsl:attribute name="idref">
                        <xsl:text>cpe:2.3:o:apple:macos:11.0:*:*:*:*:*:*:*</xsl:text>
                    </xsl:attribute>
                </xsl:element>
            </xsl:if>
            <!--<xsl:element name="platform" namespace="http://checklists.nist.gov/xccdf/1.2">
                <xsl:attribute name="idref"><xsl:text>cpe:/o:apple:macos:11.0</xsl:text></xsl:attribute>
            </xsl:element>-->
            <xsl:analyze-string select="normalize-space(//div[@class = 'docver'])" regex="^(.+)\s\(([0-9-]+)\)$">
                <xsl:matching-substring>
                    <!--<xsl:for-each select="(1, 2, 3)">
                        <xsl:message expand-text="true">{regex-group(.)}</xsl:message>
                    </xsl:for-each>-->
                    <xsl:element name="version" namespace="http://checklists.nist.gov/xccdf/1.2">
                        <xsl:attribute name="time" expand-text="true">{regex-group(2)}T00:00:00Z</xsl:attribute>
                        <xsl:attribute name="update" select="'https://github.com/usnistgov/macos_security'"/>
                        <xsl:value-of select="regex-group(1)"/>
                    </xsl:element>
                </xsl:matching-substring>
                <xsl:non-matching-substring>
                    <xsl:message expand-text="true" terminate="yes">Cannot make sense of document version {regex-group(0)}</xsl:message>
                </xsl:non-matching-substring>
            </xsl:analyze-string>
            <xsl:element name="metadata" namespace="http://checklists.nist.gov/xccdf/1.2">
                <xsl:element name="creator" namespace="http://purl.org/dc/elements/1.1/">
                    <xsl:text>National Institute of Standards and Technology</xsl:text>
                </xsl:element>
                <xsl:element name="publisher" namespace="http://purl.org/dc/elements/1.1/">
                    <xsl:text>National Institute of Standards and Technology</xsl:text>
                </xsl:element>
                <xsl:element name="source" namespace="http://purl.org/dc/elements/1.1/">
                    <xsl:text>https://github.com/usnistgov/macos_security/releases/latest</xsl:text>
                </xsl:element>
                <xsl:for-each select="//div[@class = 'sect1'][h2/@id = '_authors']//tbody/tr">
                    <xsl:element name="contributor" namespace="http://purl.org/dc/elements/1.1/" expand-text="true">{td[1]/p} — {td[2]/p}</xsl:element>
                </xsl:for-each>
            </xsl:element>
            <!--<xsl:element name="model" namespace="http://checklists.nist.gov/xccdf/1.2"/>-->
            <xsl:variable name="ROOT" as="document-node()" select="root()"/>
            <xsl:variable name="tags" as="xs:string*" select="distinct-values(//div[@class = 'sect2']//table//table//tr[th/p = 'TAGS']/td//p)"/>
            <xsl:variable name="unwanted-tags" as="xs:string*" select="('inherent', 'permanent', 'n_a', 'none', 'manual')"/>
            <xsl:variable name="desired-tags" as="xs:string*" select="sort($tags[not(. = $unwanted-tags)])"/>
            <xsl:comment expand-text="true"> Profiles for {$desired-tags} </xsl:comment>
            <xsl:for-each select="$desired-tags">
                <!--<xsl:message expand-text="true">{.} {count($ROOT//div[@class = 'sect2'][descendant::table/tbody/tr/th/p='ID'][descendant::table/descendant::tr[th/p = 'tags']/td//p = current()])}</xsl:message>-->
                <xsl:element name="Profile" namespace="http://checklists.nist.gov/xccdf/1.2">
                    <xsl:attribute name="id" expand-text="true">xccdf_{$xccdf-namespace}_profile_{.}</xsl:attribute>
                    <xsl:element name="title" namespace="http://checklists.nist.gov/xccdf/1.2" expand-text="true">{.}</xsl:element>
                    <xsl:element name="description" namespace="http://checklists.nist.gov/xccdf/1.2">
                        <xsl:text expand-text="true">This profile selects all rules tagged as {.}.</xsl:text>
                    </xsl:element>
                    <xsl:for-each select="$ROOT//div[@class = 'sect2'][descendant::table/tbody/tr/th/p = 'ID'][descendant::table/descendant::tr[th/p = 'TAGS']/td//p = current()]">
                        <xsl:variable name="id" as="xs:string" select="table/tbody/tr[1]/td//p"/>
                        <xsl:element name="select" namespace="http://checklists.nist.gov/xccdf/1.2">
                            <xsl:attribute name="idref" expand-text="true">xccdf_{$xccdf-namespace}_rule_{$id}</xsl:attribute>
                            <xsl:attribute name="selected" select="true()"/>
                        </xsl:element>
                    </xsl:for-each>
                </xsl:element>
            </xsl:for-each>
            <xsl:if test="$include-all-rule-profile">
                <!--<xsl:message expand-text="true">{count($ROOT//div[@class = 'sect2'][descendant::table/tbody/tr/th/p='ID'])} rules</xsl:message>-->
                <xsl:element name="Profile" namespace="http://checklists.nist.gov/xccdf/1.2">
                    <xsl:attribute name="id" expand-text="true">xccdf_{$xccdf-namespace}_profile_all</xsl:attribute>
                    <xsl:element name="title" namespace="http://checklists.nist.gov/xccdf/1.2">
                        <xsl:text>All</xsl:text>
                    </xsl:element>
                    <xsl:element name="description" namespace="http://checklists.nist.gov/xccdf/1.2">
                        <xsl:text>This profile includes all checklist rules.</xsl:text>
                    </xsl:element>
                    <xsl:for-each select="//div[@class = 'sect2'][descendant::table/tbody/tr/th/p = 'ID']">
                        <xsl:variable name="id" as="xs:string" select="table/tbody/tr[1]/td//p"/>
                        <xsl:element name="select" namespace="http://checklists.nist.gov/xccdf/1.2">
                            <xsl:attribute name="idref" expand-text="true">xccdf_{$xccdf-namespace}_rule_{$id}</xsl:attribute>
                            <xsl:attribute name="selected" select="true()"/>
                        </xsl:element>
                    </xsl:for-each>
                </xsl:element>
            </xsl:if>
            <xsl:for-each select="//div[@class = 'sect1'][h2][descendant::div[@class = 'sect2'][h3][table//p = 'ID']]">
                <xsl:element name="Group" namespace="http://checklists.nist.gov/xccdf/1.2">
                    <xsl:attribute name="id" expand-text="true">xccdf_{$xccdf-namespace}_group{child::h2/@id}</xsl:attribute>
                    <xsl:element name="title" namespace="http://checklists.nist.gov/xccdf/1.2">
                        <xsl:value-of select="fn:retitle(child::h2)"/>
                    </xsl:element>
                    <xsl:element name="description" namespace="http://checklists.nist.gov/xccdf/1.2">
                        <xsl:element name="div" namespace="http://www.w3.org/1999/xhtml">
                            <xsl:apply-templates mode="html" select="child::div[@class = 'sectionbody']/div[@class != 'sect2']"/>
                        </xsl:element>
                    </xsl:element>
                    <xsl:if test="child::div[@class = 'sectionbody']/child::div[matches(@class, 'admonitionblock')]">
                        <xsl:for-each select="child::div[@class = 'sectionbody']/child::div[matches(@class, 'admonitionblock')]">
                            <xsl:element name="warning" namespace="http://checklists.nist.gov/xccdf/1.2">
                                <xsl:attribute name="category" select="'general'"/>
                                <xsl:apply-templates mode="warning" select="current()"/>
                            </xsl:element>
                        </xsl:for-each>
                    </xsl:if>
                    <xsl:variable name="notchecked" as="xs:string*" select="('_not_applicable', '_inherent', '_permanent_findings')"/>
                    <xsl:variable name="notapplicable" as="xs:string*" select="('_not_applicable')"/>
                    <xsl:for-each select="descendant::div[@class = 'sect2'][h3][table//p = 'ID']">
                        <xsl:element name="Rule" namespace="http://checklists.nist.gov/xccdf/1.2">
                            <xsl:variable name="rule-id" as="xs:string" select="table/tbody/tr[1]/td//p"/>
                            <xsl:variable name="id" as="xs:string" select="$rule-id"/>
                            <xsl:attribute name="id" expand-text="true">xccdf_{$xccdf-namespace}_rule_{$id}</xsl:attribute>
                            <xsl:variable name="ocil" as="xs:string" select="'ocil.xml'"/>
                            <xsl:attribute name="selected" select="false()"/>
                            <xsl:variable name="OVAL-definition" as="xs:string*">
                                <xsl:choose xpath-default-namespace="http://oval.mitre.org/XMLSchema/oval-definitions-5">
                                    <xsl:when test="$OVAL-document//definition[metadata/reference[@source = 'macos_security' and @ref_id = $rule-id]]/@id">
                                        <xsl:for-each select="$OVAL-document//definition[metadata/reference[@source = 'macos_security' and @ref_id = $rule-id]]/@id">
                                            <xsl:value-of select="."/>
                                        </xsl:for-each>
                                    </xsl:when>
                                </xsl:choose>
                            </xsl:variable>
                            <!--<xsl:message expand-text="true">{$rule-id} OVAL-definition count: {count($OVAL-definition)}</xsl:message>-->
                            <xsl:variable name="role" as="xs:string">
                                <xsl:choose>
                                    <xsl:when test="ancestor::div[@class = 'sect1']/h2[@id = $notchecked]">
                                        <xsl:text>unchecked</xsl:text>
                                    </xsl:when>
                                    <xsl:when test="$OVAL-document//definition[metadata/reference[@source = 'macos_security' and @ref_id = $rule-id]]"
                                        xpath-default-namespace="http://oval.mitre.org/XMLSchema/oval-definitions-5">
                                        <xsl:text>full</xsl:text>
                                    </xsl:when>
                                    <xsl:otherwise>
                                        <xsl:text>unchecked</xsl:text>
                                    </xsl:otherwise>
                                </xsl:choose>
                            </xsl:variable>
                            <xsl:attribute name="role" select="$role"/>
                            <xsl:attribute name="severity" select="'unknown'"/>
                            <xsl:attribute name="weight" select="'1.0'"/>
                            <xsl:element name="title" namespace="http://checklists.nist.gov/xccdf/1.2">
                                <xsl:value-of select="fn:retitle(h3)"/>
                            </xsl:element>
                            <xsl:element name="description" namespace="http://checklists.nist.gov/xccdf/1.2">
                                <xsl:element name="div" namespace="http://www.w3.org/1999/xhtml">
                                    <xsl:apply-templates mode="html" select="div"/>
                                </xsl:element>
                            </xsl:element>
                            <xsl:choose>
                                <xsl:when test="table/tbody/tr[2]/td/div/table/tbody/tr[2]/td//li/p">
                                    <!-- has CCE -->
                                </xsl:when>
                                <xsl:otherwise>
                                    <xsl:element name="warning" namespace="http://checklists.nist.gov/xccdf/1.2">
                                        <div xmlns="http://www.w3.org/1999/xhtml">
                                            <xsl:text expand-text="true">This rule lacks a CCE designation (required for SCAP compliance). </xsl:text>
                                            <!--<a href="https://csrc.nist.gov/publications/detail/sp/800-126/rev-3/final">https://csrc.nist.gov/publications/detail/sp/800-126/rev-3/final §3.2.4.1</a>-->
                                        </div>
                                    </xsl:element>
                                </xsl:otherwise>
                            </xsl:choose>
                            <xsl:if test="descendant::div[matches(@class, 'admonitionblock')]">
                                <xsl:element name="warning" namespace="http://checklists.nist.gov/xccdf/1.2">
                                    <xsl:attribute name="category" select="'general'"/>
                                    <xsl:apply-templates mode="warning" select="descendant::div[matches(@class, 'admonitionblock')]"/>
                                </xsl:element>
                            </xsl:if>
                            <!--<xsl:element name="reference" namespace="http://checklists.nist.gov/xccdf/1.2">
                                <xsl:text>ruleID=</xsl:text>
                                <xsl:value-of select="$id"/>
                            </xsl:element>-->
                            <!-- FIXME: imprecise selector -->
                            <xsl:for-each select="table/tbody/tr[2]/td/div/table/tbody/tr[1]/td//li/p">
                                <xsl:for-each select="tokenize(., ',\s+')">
                                    <xsl:element name="reference" namespace="http://checklists.nist.gov/xccdf/1.2">
                                        <xsl:attribute name="href">
                                            <xsl:text>https://nvd.nist.gov/800-53/Rev5/control/</xsl:text>
                                            <xsl:choose>
                                                <xsl:when test="matches(., '[A-Z]{2}-\d+$')">
                                                    <xsl:value-of select="."/>
                                                </xsl:when>
                                                <xsl:when test="matches(., '[A-Z]{2}-\d+\([a-z]\)$')">
                                                    <xsl:value-of select="replace(., '\([a-z]\)$', '')"/>
                                                </xsl:when>
                                                <xsl:when test="matches(., '[A-Z]{2}-\d+\(\d+\).*$')">
                                                    <xsl:value-of select="replace(., '\((\d+)\).*$', '#enhancement-$1')"/>
                                                </xsl:when>
                                            </xsl:choose>
                                        </xsl:attribute>
                                        <xsl:text>NIST SP 800-53r5 </xsl:text>
                                        <xsl:value-of select="."/>
                                    </xsl:element>
                                </xsl:for-each>
                            </xsl:for-each>
                            <!-- FIXME: imprecise selector -->
                            <xsl:choose>
                                <xsl:when test="descendant::tr[th/p = 'CCE']">
                                    <!-- has CCE -->
                                    <xsl:for-each select="descendant::tr[th/p = 'CCE']/td//li/p">
                                        <xsl:element name="ident" namespace="http://checklists.nist.gov/xccdf/1.2">
                                            <xsl:attribute name="system" select="'http://cce.mitre.org/'"/>
                                            <xsl:value-of select="."/>
                                        </xsl:element>
                                    </xsl:for-each>
                                </xsl:when>
                                <xsl:otherwise>
                                    <!--<xsl:element name="ident" namespace="http://checklists.nist.gov/xccdf/1.2"> <xsl:attribute name="system">https://nvd.nist.gov/cce/index.cfm</xsl:attribute> <xsl:value-of select="'CCE-FIXME'"/> </xsl:element>-->
                                </xsl:otherwise>
                            </xsl:choose>
                            <!-- FIXME: imprecise selector -->
                            <xsl:if test="child::div[@class = 'exampleblock']">
                                <xsl:element name="fixtext" namespace="http://checklists.nist.gov/xccdf/1.2">
                                    <xsl:apply-templates mode="fixtext" select="child::div[@class = 'exampleblock']"/>
                                </xsl:element>
                            </xsl:if>
                            <xsl:choose>
                                <xsl:when test="count($OVAL-definition) = 0">
                                    <xsl:comment> (no OVAL check(s) </xsl:comment>
                                    <xsl:element name="check" namespace="http://checklists.nist.gov/xccdf/1.2">
                                        <xsl:attribute name="system" select="'http://scap.nist.gov/schema/ocil/2'"/>
                                        <xsl:element name="check-content-ref" namespace="http://checklists.nist.gov/xccdf/1.2">
                                            <xsl:attribute name="href" select="$ocil"/>
                                        </xsl:element>
                                    </xsl:element>
                                </xsl:when>
                                <xsl:when test="count($OVAL-definition) = 1">
                                    <xsl:element name="check" namespace="http://checklists.nist.gov/xccdf/1.2">
                                        <xsl:attribute name="system" select="'http://oval.mitre.org/XMLSchema/oval-definitions-5'"/>
                                        <xsl:element name="check-content-ref" namespace="http://checklists.nist.gov/xccdf/1.2">
                                            <xsl:attribute name="href" select="'oval.xml'"/>
                                            <xsl:attribute name="name" select="$OVAL-definition"/>
                                        </xsl:element>
                                    </xsl:element>
                                </xsl:when>
                                <xsl:when test="count($OVAL-definition) != 1">
                                    <xsl:element name="complex-check" namespace="http://checklists.nist.gov/xccdf/1.2">
                                        <xsl:attribute name="operator">AND</xsl:attribute>
                                        <xsl:for-each select="$OVAL-definition">
                                            <xsl:element name="check" namespace="http://checklists.nist.gov/xccdf/1.2">
                                                <xsl:attribute name="system" select="'http://oval.mitre.org/XMLSchema/oval-definitions-5'"/>
                                                <xsl:element name="check-content-ref" namespace="http://checklists.nist.gov/xccdf/1.2">
                                                    <xsl:attribute name="href" select="'oval.xml'"/>
                                                    <xsl:attribute name="name" select="current()"/>
                                                </xsl:element>
                                            </xsl:element>
                                        </xsl:for-each>
                                    </xsl:element>
                                </xsl:when>
                            </xsl:choose>
                        </xsl:element>
                    </xsl:for-each>
                </xsl:element>
            </xsl:for-each>
        </xsl:element>
    </xsl:template>
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl" scope="stylesheet">
        <xd:desc>
            <xd:p><xd:b>Created on:</xd:b> Jun 8, 2020</xd:p>
            <xd:p><xd:b>Author:</xd:b> gapinski</xd:p>
            <xd:p>Transform non-namespaced HTML to namespaced HTML</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:template mode="html" match="element()">
        <xsl:choose>
            <xsl:when test="name() = 'div' and matches(@class, 'exampleblock')"/>
            <xsl:when test="name() = 'div' and matches(@class, 'admonitionblock')">
                <!--<xsl:element name="div" namespace="http://www.w3.org/1999/xhtml"> <xsl:attribute name="style">font-weight: bold;</xsl:attribute> <xsl:apply-templates mode="html" select="descendant::td[@class = 'content']/node()"/> </xsl:element>-->
            </xsl:when>
            <xsl:when test="matches(name(), 'h1|h2|h3|h4|h5|h6|table')">
                <!-- ignore -->
            </xsl:when>
            <xsl:when test="name() = 'pre'">
                <xsl:element name="{name()}" namespace="http://www.w3.org/1999/xhtml">
                    <xsl:copy-of select=".//text()"/>
                </xsl:element>
            </xsl:when>
            <xsl:when test="not(descendant::element())">
                <xsl:value-of select="normalize-space(.)"/>
            </xsl:when>
            <xsl:otherwise>
                <xsl:element name="{name()}" namespace="http://www.w3.org/1999/xhtml">
                    <xsl:copy-of select="attribute::node()[name() != 'class']">
                        <!-- we do not care a fig for CSS -->
                    </xsl:copy-of>
                    <xsl:apply-templates mode="html"/>
                </xsl:element>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl" scope="stylesheet">
        <xd:desc>
            <xd:p><xd:b>Created on:</xd:b> Jun 8, 2020</xd:p>
            <xd:p><xd:b>Author:</xd:b> gapinski</xd:p>
            <xd:p>Transform non-namespaced HTML to namespaced HTML</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:template mode="warning" match="element()">
        <xsl:choose>
            <xsl:when test="name() = 'div' and matches(@class, 'admonitionblock')">
                <xsl:element name="div" namespace="http://www.w3.org/1999/xhtml">
                    <!--<xsl:attribute name="style">font-weight: bold;</xsl:attribute>-->
                    <xsl:apply-templates mode="warning" select="descendant::td[@class = 'content']/node()"/>
                </xsl:element>
            </xsl:when>
            <xsl:when test="matches(name(), 'h1|h2|h3|h4|h5|h6|table')">
                <!-- ignore -->
            </xsl:when>
            <xsl:when test="name() = 'pre'">
                <xsl:element name="{name()}" namespace="http://www.w3.org/1999/xhtml">
                    <xsl:copy-of select=".//text()"/>
                </xsl:element>
            </xsl:when>
            <xsl:when test="not(descendant::element())">
                <xsl:value-of select="normalize-space(.)"/>
            </xsl:when>
            <xsl:otherwise>
                <xsl:element name="{name()}" namespace="http://www.w3.org/1999/xhtml">
                    <xsl:copy-of select="attribute::node()[name() != 'class']">
                        <!-- we do not care a fig for CSS -->
                    </xsl:copy-of>
                    <xsl:apply-templates mode="warning"/>
                </xsl:element>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>
    <xd:doc xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl" scope="stylesheet">
        <xd:desc>
            <xd:p><xd:b>Created on:</xd:b> Jun 8, 2020</xd:p>
            <xd:p><xd:b>Author:</xd:b> gapinski</xd:p>
            <xd:p>Transform non-namespaced HTML to namespaced HTML</xd:p>
        </xd:desc>
    </xd:doc>
    <xsl:template mode="fixtext" match="element()">
        <xsl:choose>
            <xsl:when test="name() = 'div' and matches(@class, 'exampleblock')">
                <xsl:element name="div" namespace="http://www.w3.org/1999/xhtml">
                    <xsl:apply-templates mode="fixtext" select="child::div/*[position() &gt; 2]"/>
                </xsl:element>
            </xsl:when>
            <xsl:when test="name() = 'pre'">
                <xsl:element name="{name()}" namespace="http://www.w3.org/1999/xhtml">
                    <xsl:copy-of select=".//text()"/>
                </xsl:element>
            </xsl:when>
            <xsl:when test="not(descendant::element())">
                <xsl:value-of select="normalize-space(.)"/>
            </xsl:when>
            <xsl:otherwise>
                <xsl:element name="{name()}" namespace="http://www.w3.org/1999/xhtml">
                    <xsl:copy-of select="attribute::node()[name() != 'class']">
                        <!-- we do not care a fig for CSS -->
                    </xsl:copy-of>
                    <xsl:apply-templates mode="fixtext"/>
                </xsl:element>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>
</xsl:stylesheet>
