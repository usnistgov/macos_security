<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" exclude-result-prefixes="xs" version="3.0" xmlns:cpe="http://cpe.mitre.org/language/2.0"
    xmlns:uuid="java.util.UUID">
    <!-- generate an SCAP datastream collection -->
    <!-- this transformation expects a single XCCDF 1.2 document and creates an SCAP datastream collection consisting of the XCCDF document and any related documents -->
    <!--  -->
    <xsl:param name="SCAP-version" as="xs:decimal" required="no" select="1.3"/>
    <!-- "namespace" for identifiers -->
    <xsl:param name="id-namespace" as="xs:string" required="yes"/>
    <xsl:variable name="dsc-namespace" as="xs:string" select="string-join(reverse(tokenize($id-namespace, '\.')), '.')"/>
    <!-- It is not necessary to emit namespaces. This transform takes pains to cite namespaces rather than prefixes to avoid prefix collisions. -->
    <xsl:param name="emit-namespaces" as="xs:boolean" required="no" select="false()"/>
    <!-- It is not necessary to emit schema locations. This transform expects XML Catalog will be used to associate namespaces with schemata. -->
    <xsl:param name="emit-schemaLocation" as="xs:boolean" required="no" select="false()"/>
    <!-- CPE references are not included by default -->
    <xsl:param name="include-CPE" as="xs:boolean" required="no" select="true()"/>
    <!-- Indent output document -->
    <xsl:param name="indent-output" as="xs:boolean" required="no" select="false()" static="true"/>
    <xsl:strip-space elements="*"/>
    <xsl:output method="xml"/>
    <xsl:output use-when="$indent-output" indent="true"/>
    <!-- list of namespaces -->
    <xsl:variable name="namespaces" as="element()*">
        <scap version="1.2">
            <!-- SCAP -->
            <namespace prefix="ds" namespace="http://scap.nist.gov/schema/scap/source/1.2" schema="http://scap.nist.gov/schema/scap/1.2/scap-source-data-stream_1.2.xsd"/>
            <namespace prefix="xlink" namespace="http://www.w3.org/1999/xlink"/>
            <namespace prefix="cat" namespace="urn:oasis:names:tc:entity:xmlns:xml:catalog"/>
            <namespace prefix="xsi" namespace="http://www.w3.org/2001/XMLSchema-instance"/>
            <!-- XCCDF -->
            <namespace prefix="xccdf" namespace="http://checklists.nist.gov/xccdf/1.2" schema="http://scap.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd"/>
            <!-- TODO: OVAL -->
        </scap>
        <scap version="1.3">
            <!-- SCAP -->
            <namespace prefix="ds" namespace="http://scap.nist.gov/schema/scap/source/1.3" schema="https://csrc.nist.gov/schema/scap/1.3/scap-source-data-stream_1.3.xsd"/>
            <namespace prefix="xlink" namespace="http://www.w3.org/1999/xlink"/>
            <namespace prefix="cat" namespace="urn:oasis:names:tc:entity:xmlns:xml:catalog"/>
            <namespace prefix="xsi" namespace="http://www.w3.org/2001/XMLSchema-instance"/>
            <!-- XCCDF -->
            <namespace prefix="xccdf" namespace="http://checklists.nist.gov/xccdf/1.2" schema="http://scap.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd"/>
            <!-- TODO: OVAL -->
        </scap>
    </xsl:variable>
    <!-- time stamp -->
    <xsl:variable name="Z" as="xs:duration" select="xs:dayTimeDuration('PT0H')"/>
    <xsl:variable name="T" select="adjust-dateTime-to-timezone(current-dateTime(), $Z)"/>
    <!-- NIST has the obdurate idea that all sorts of IDs should be "globally unique"¹ — via fiat rather than technical means -->
    <!-- This will guarantee that — generate a UUID! -->
    <!--<xsl:variable name="dsc-unique-suffix" select="uuid:randomUUID()"/>-->
    <xsl:param name="datastream-id-suffix" as="xs:string" required="true"/>
    <!-- ¹ But only if one does not copy a document output and modify the copy -->
    <xsl:variable name="XCCDF" as="document-node()" select="/"/>
    <xsl:variable name="LF" as="xs:string" select="'&#x0a;'"/>
    <xsl:template match="/">
        <xsl:copy-of select="$LF"/>
        <xsl:copy-of select="$LF"/>
        <xsl:comment expand-text="true"> This is an SCAP {$SCAP-version} datastream collection document </xsl:comment>
        <xsl:copy-of select="$LF"/>
        <xsl:comment expand-text="true"> Created {$T} </xsl:comment>
        <xsl:copy-of select="$LF"/>
        <xsl:comment expand-text="true"> using {static-base-uri()} with {resolve-uri(base-uri())} as input </xsl:comment>
        <xsl:copy-of select="$LF"/>
        <xsl:comment expand-text="true"> The SCAP identifier "namespace" chosen for this data stream collection is «{$dsc-namespace}» («{$id-namespace}» reversed) </xsl:comment>
        <xsl:copy-of select="$LF"/>
        <!-- See https://www.w3.org/TR/xml-model/ -->
        <xsl:copy-of select="$LF"/>
        <xsl:comment> See https://www.w3.org/TR/xml-model/ for an explanation of the following processing instruction </xsl:comment>
        <xsl:copy-of select="$LF"/>
        <xsl:processing-instruction name="xml-model">
            <xsl:text>href="https://csrc.nist.gov/schema/scap/1.3/scap-source-data-stream_1.3.xsd"</xsl:text>
            <xsl:text> </xsl:text>
            <xsl:text>schematypens="http://www.w3.org/2001/XMLSchema"</xsl:text>
            <xsl:text> </xsl:text>
            <xsl:text>title="SCAP XML schema"</xsl:text>
        </xsl:processing-instruction>
        <!-- See https://www.w3.org/TR/xml-stylesheet/ -->
        <xsl:copy-of select="$LF"/>
        <xsl:if test="false()">
            <xsl:copy-of select="$LF"/>
            <xsl:comment> See https://www.w3.org/TR/xml-stylesheet/ for an explanation of the following processing instruction </xsl:comment>
            <xsl:copy-of select="$LF"/>
            <xsl:processing-instruction name="xml-stylesheet">
                <xsl:text>type="text/xsl"</xsl:text>    
                <xsl:text> </xsl:text>
                <xsl:text>href=""</xsl:text>
                <xsl:text> </xsl:text>
                <xsl:text>title=""</xsl:text>
            </xsl:processing-instruction>
            <xsl:copy-of select="$LF"/>
        </xsl:if>
        <!--<xsl:comment select="concat('The UUID chosen for this data stream collection is «', $dsc-unique-suffix, '» which ensures the preservation of Global Uniqueness™')"/>-->
        <!-- create the collection -->
        <xsl:copy-of select="$LF"/>
        <xsl:element name="data-stream-collection" namespace="http://scap.nist.gov/schema/scap/source/1.2">
            <xsl:attribute name="id" expand-text="true">scap_{$dsc-namespace}_collection_{$datastream-id-suffix}</xsl:attribute>
            <xsl:attribute name="schematron-version" select="$SCAP-version"/>
            <xsl:if test="$emit-namespaces">
                <xsl:for-each select="$namespaces[@version = $SCAP-version]/namespace">
                    <xsl:message expand-text="true">
                        <xsl:namespace name="{@prefix}" select="@namespace"/>
                    </xsl:message>
                    <xsl:namespace name="{@prefix}" select="@namespace"/>
                </xsl:for-each>
            </xsl:if>
            <xsl:if test="$emit-schemaLocation">
                <xsl:attribute name="schemaLocation" namespace="http://www.w3.org/2001/XMLSchema-instance">
                    <xsl:for-each select="$namespaces[@version = $SCAP-version]/namespace[@schema]">
                        <xsl:if test="
                                (: separate pairs :)
                                position() != 1">
                            <xsl:text>&#x20;</xsl:text>
                        </xsl:if>
                        <xsl:value-of select="string-join((@namespace, @schema), ' ')"/>
                    </xsl:for-each>
                </xsl:attribute>
            </xsl:if>
            <!-- create the data stream -->
            <xsl:element name="data-stream" namespace="http://scap.nist.gov/schema/scap/source/1.2">
                <xsl:attribute name="timestamp" select="$T"/>
                <xsl:attribute name="id" expand-text="true">scap_{$dsc-namespace}_datastream_{$datastream-id-suffix}</xsl:attribute>
                <xsl:attribute name="scap-version" select="$SCAP-version"/>
                <xsl:attribute name="use-case">CONFIGURATION</xsl:attribute>
                <xsl:if test="$include-CPE">
                    <!--
                        Create a <dictionaries> section
                        Dictionaries are used only for CPE-related constructs
                        An XML Catalog is needed to equate (XCCDF-relative) relative references with <component-refs>
                        (The <component-refs> in turn reference <components>)
                    -->
                    <xsl:if test="//reference[. = 'platform-cpe-dictionary'][@href]" xpath-default-namespace="http://checklists.nist.gov/xccdf/1.2">
                        <xsl:element name="dictionaries" namespace="http://scap.nist.gov/schema/scap/source/1.2">
                            <!-- create a reference for each CPE reference -->
                            <xsl:for-each select="//reference[. = 'platform-cpe-dictionary'][@href]" xpath-default-namespace="http://checklists.nist.gov/xccdf/1.2">
                                <xsl:element name="component-ref" namespace="http://scap.nist.gov/schema/scap/source/1.2">
                                    <!-- the @id is arbitrary -->
                                    <xsl:attribute name="id" expand-text="true">scap_{$dsc-namespace}_cref_{$datastream-id-suffix}_{@href}</xsl:attribute>
                                    <xsl:attribute name="type" namespace="http://www.w3.org/1999/xlink" select="'simple'"/>
                                    <!-- the href should reference a subsequently produced <component>/@id -->
                                    <xsl:attribute name="href" namespace="http://www.w3.org/1999/xlink">
                                        <xsl:text>#</xsl:text>
                                        <xsl:value-of select="concat('scap_', $dsc-namespace, '_comp_', $datastream-id-suffix, '_', @href)"/>
                                    </xsl:attribute>
                                    <!-- 
                                        Create a context catalog for any cpe-dictionary referenced check 
                                        The catalog provides a mapping from a cpe-dictionary reference to the relative cpe-oval 
                                    -->
                                    <xsl:variable name="cpe-list" as="document-node()" select="doc(@href)"/>
                                    <xsl:element name="catalog" namespace="urn:oasis:names:tc:entity:xmlns:xml:catalog">
                                        <!-- reference each check component -->
                                        <xsl:for-each select="distinct-values($cpe-list//check/@href)" xpath-default-namespace="http://cpe.mitre.org/dictionary/2.0">
                                            <xsl:element name="uri" namespace="urn:oasis:names:tc:entity:xmlns:xml:catalog">
                                                <xsl:attribute name="name">
                                                    <xsl:value-of select="."/>
                                                </xsl:attribute>
                                                <!-- the URI should reference a (subsequently-produced) <component-ref> which in turn referencves the component -->
                                                <xsl:attribute name="uri">
                                                    <xsl:text expand-text="true">#scap_{$dsc-namespace}_cref_{$datastream-id-suffix}_{.}</xsl:text>
                                                    
                                                </xsl:attribute>
                                            </xsl:element>
                                        </xsl:for-each>
                                    </xsl:element>
                                </xsl:element>
                            </xsl:for-each>
                        </xsl:element>
                    </xsl:if>
                    <!--<xsl:if test="//cpe:platform-specification">
                       <xsl:element name="dictionaries" namespace="http://scap.nist.gov/schema/scap/source/1.2">
                           <xsl:for-each select="//cpe:check-fact-ref">
                               <xsl:element name="component-ref" namespace="http://scap.nist.gov/schema/scap/source/1.2">
                                   <xsl:attribute name="id" select="concat('scap_', $dsc-namespace,'_cref_', $dsc-unique-suffix, '_', 'dict', '_', position())"/>
                                   <xsl:attribute name="type" namespace="http://www.w3.org/1999/xlink" select="'simple'"/>
                                   <xsl:attribute name="href" namespace="http://www.w3.org/1999/xlink">
                                       <xsl:text>#</xsl:text>
                                       <xsl:value-of select="concat('scap_', $dsc-namespace,'_cref_', $dsc-unique-suffix, '_', 'dict', '_', position())"/>
                                   </xsl:attribute>
                               </xsl:element>
                           </xsl:for-each>
                       </xsl:element>
                   </xsl:if>-->
                    <!--<xsl:element name="dictionaries" namespace="http://scap.nist.gov/schema/scap/source/1.2">
                       <xsl:element name="component-ref" namespace="http://scap.nist.gov/schema/scap/source/1.2">
                           <xsl:attribute name="id"
                                select="concat('scap_', $dsc-namespace,'_cref_', $dsc-unique-suffix, '_', 'gratuitous&#xb7;cpe&#xb7;dictionary')"/>
                           <xsl:attribute name="type" namespace="http://www.w3.org/1999/xlink" select="'simple'"/>
                           <xsl:attribute name="href" namespace="http://www.w3.org/1999/xlink">
                               <xsl:text>#</xsl:text>
                               <xsl:value-of select="concat('scap_', $dsc-namespace,'_comp_', $dsc-unique-suffix, '_', 'gratuitous&#xb7;cpe&#xb7;dictionary')"/>
                           </xsl:attribute>
                       </xsl:element>
                   </xsl:element>-->
                </xsl:if>
                <xsl:element name="checklists" namespace="http://scap.nist.gov/schema/scap/source/1.2">
                    <!-- reference the checklist component -->
                    <xsl:element name="component-ref" namespace="http://scap.nist.gov/schema/scap/source/1.2">
                        <!--<xsl:attribute name="id"
                            select="concat('scap_', $dsc-namespace, '_cref_', $dsc-unique-suffix, '_', tokenize(base-uri(), '/')[last()])"/>-->
                        <xsl:attribute name="id" expand-text="true">scap_{$dsc-namespace}_cref_{$datastream-id-suffix}_{tokenize(base-uri(), '/')[last()]}</xsl:attribute>
                        <xsl:attribute name="type" namespace="http://www.w3.org/1999/xlink" select="'simple'"/>
                        <xsl:attribute name="href" namespace="http://www.w3.org/1999/xlink">
                            <xsl:text>#</xsl:text>
                            <xsl:value-of select="concat('scap_', $dsc-namespace, '_comp_', $datastream-id-suffix, '_', tokenize(base-uri(), '/')[last()])"/>
                        </xsl:attribute>
                        <!--<xsl:comment expand-text="true">Original document URI was «{base-uri()}»</xsl:comment>-->
                        <!-- create a context catalog -->
                        <xsl:element name="catalog" namespace="urn:oasis:names:tc:entity:xmlns:xml:catalog">
                            <!-- reference each check component -->
                            <xsl:for-each select="distinct-values(//check-content-ref/@href)" xpath-default-namespace="http://checklists.nist.gov/xccdf/1.2">
                                <xsl:element name="uri" namespace="urn:oasis:names:tc:entity:xmlns:xml:catalog">
                                    <xsl:attribute name="name">
                                        <xsl:value-of select="."/>
                                    </xsl:attribute>
                                    <xsl:attribute name="uri">
                                        <xsl:text>#</xsl:text>
                                        <xsl:value-of select="concat('scap_', $dsc-namespace, '_cref_', $datastream-id-suffix, '_', 'check', '_', position())"/>
                                    </xsl:attribute>
                                    <!--<xsl:choose>
                                       <xsl:when test="matches(., '^(file:|http|:https:)')">
                                           <xsl:comment>
                                               <xsl:text>Original intra-XCCDF reference was «</xsl:text>
                                               <xsl:value-of select="."/>
                                               <xsl:text>»</xsl:text>
                                           </xsl:comment>
                                       </xsl:when>
                                       <xsl:otherwise>
                                           <xsl:comment>
                                               <xsl:text>Original intra-XCCDF reference was «</xsl:text>
                                               <xsl:value-of select="."/>
                                               <xsl:text>»</xsl:text>
                                               <xsl:text> relative to the XCCDF document</xsl:text>
                                           </xsl:comment>
                                       </xsl:otherwise>
                                   </xsl:choose>-->
                                </xsl:element>
                            </xsl:for-each>
                            <xsl:for-each select="distinct-values(//cpe:check-fact-ref/@href)" xpath-default-namespace="http://checklists.nist.gov/xccdf/1.2">
                                <xsl:element name="uri" namespace="urn:oasis:names:tc:entity:xmlns:xml:catalog">
                                    <xsl:attribute name="name">
                                        <xsl:value-of select="."/>
                                    </xsl:attribute>
                                    <xsl:attribute name="uri">
                                        <xsl:text>#</xsl:text>
                                        <xsl:value-of select="concat('scap_', $dsc-namespace, '_cref_', $datastream-id-suffix, '_', 'cpe', '_', position())"/>
                                    </xsl:attribute>
                                    <xsl:choose>
                                        <xsl:when test="matches(., '^(file:|http|:https:)')">
                                            <xsl:comment expand-text="true">Original intra-XCCDF reference was «{.}»</xsl:comment>
                                        </xsl:when>
                                        <xsl:otherwise>
                                            <xsl:comment expand-text="true">Original intra-XCCDF reference was «{.}» relative to the XCCDF
                                                document</xsl:comment>
                                        </xsl:otherwise>
                                    </xsl:choose>
                                </xsl:element>
                            </xsl:for-each>
                        </xsl:element>
                    </xsl:element>
                </xsl:element>
                <xsl:element name="checks" namespace="http://scap.nist.gov/schema/scap/source/1.2">
                    <!-- include CPE-related checks -->
                    <xsl:if test="$include-CPE">
                        <!-- define all check components referenced from CPE -->
                        <xsl:for-each select="//reference[. = 'platform-cpe-dictionary'][@href]" xpath-default-namespace="http://checklists.nist.gov/xccdf/1.2">
                            <xsl:for-each select="distinct-values(doc(@href)//check/@href)" xpath-default-namespace="http://cpe.mitre.org/dictionary/2.0">
                                <xsl:element name="component-ref" namespace="http://scap.nist.gov/schema/scap/source/1.2">
                                    <xsl:attribute name="id" select="concat('scap_', $dsc-namespace, '_cref_', $datastream-id-suffix, '_', .)"/>
                                    <xsl:attribute name="type" namespace="http://www.w3.org/1999/xlink" select="'simple'"/>
                                    <xsl:attribute name="href" namespace="http://www.w3.org/1999/xlink">
                                        <xsl:text>#</xsl:text>
                                        <xsl:value-of select="concat('scap_', $dsc-namespace, '_comp_', $datastream-id-suffix, '_', .)"/>
                                    </xsl:attribute>
                                </xsl:element>
                            </xsl:for-each>
                        </xsl:for-each>
                    </xsl:if>
                    <!-- define all check components referenced from check-content-ref -->
                    <xsl:for-each select="distinct-values(//check-content-ref/@href)" xpath-default-namespace="http://checklists.nist.gov/xccdf/1.2">
                        <xsl:element name="component-ref" namespace="http://scap.nist.gov/schema/scap/source/1.2">
                            <xsl:attribute name="id" select="concat('scap_', $dsc-namespace, '_cref_', $datastream-id-suffix, '_', 'check', '_', position())"/>
                            <xsl:attribute name="type" namespace="http://www.w3.org/1999/xlink" select="'simple'"/>
                            <xsl:attribute name="href" namespace="http://www.w3.org/1999/xlink">
                                <xsl:choose>
                                    <xsl:when test="matches(., '^\w+:')">
                                        <xsl:value-of select="."/>
                                    </xsl:when>
                                    <xsl:otherwise>
                                        <xsl:text>#</xsl:text>
                                        <xsl:value-of select="concat('scap_', $dsc-namespace, '_comp_', $datastream-id-suffix, '_', 'check', '_', position())"/>
                                    </xsl:otherwise>
                                </xsl:choose>
                            </xsl:attribute>
                        </xsl:element>
                    </xsl:for-each>
                </xsl:element>
            </xsl:element>
            <!-- include checklist component -->
            <xsl:element name="component" namespace="http://scap.nist.gov/schema/scap/source/1.2">
                <xsl:attribute name="id" select="concat('scap_', $dsc-namespace, '_comp_', $datastream-id-suffix, '_', tokenize(base-uri(), '/')[last()])"/>
                <xsl:attribute name="timestamp" select="$T"/>
                <xsl:comment expand-text="true">This is the content from «{base-uri()}»</xsl:comment>
                <xsl:copy-of select="/"/>
            </xsl:element>
            <!-- include all check components -->
            <xsl:variable name="base" select="base-uri()"/>
            <xsl:for-each select="distinct-values(//check-content-ref/@href[not(matches(., '^\w+:'))])" xpath-default-namespace="http://checklists.nist.gov/xccdf/1.2">
                <xsl:element name="component" namespace="http://scap.nist.gov/schema/scap/source/1.2">
                    <xsl:attribute name="id" select="concat('scap_', $dsc-namespace, '_comp_', $datastream-id-suffix, '_', 'check', '_', position())"/>
                    <xsl:attribute name="timestamp" select="$T"/>
                    <xsl:comment expand-text="true">This is the content from «{resolve-uri(., $base)}»</xsl:comment>
                    <xsl:apply-templates mode="selective-copy" select="doc(resolve-uri(., $base))"/>
                </xsl:element>
            </xsl:for-each>
            <xsl:if test="$include-CPE">
                <!-- include all CPE components -->
                <xsl:for-each select="//reference[. = 'platform-cpe-dictionary'][@href]" xpath-default-namespace="http://checklists.nist.gov/xccdf/1.2">
                    <xsl:element name="component" namespace="http://scap.nist.gov/schema/scap/source/1.2">
                        <xsl:attribute name="id" select="concat('scap_', $dsc-namespace, '_comp_', $datastream-id-suffix, '_', @href)"/>
                        <xsl:attribute name="timestamp" select="$T"/>
                        <xsl:comment expand-text="true">This is the content from «{resolve-uri(@href, $base)}»</xsl:comment>
                        <xsl:copy-of select="doc(@href)"/>
                    </xsl:element>
                    <xsl:for-each select="distinct-values(doc(@href)//check/@href)" xpath-default-namespace="http://cpe.mitre.org/dictionary/2.0">
                        <xsl:element name="component" namespace="http://scap.nist.gov/schema/scap/source/1.2">
                            <xsl:attribute name="id" select="concat('scap_', $dsc-namespace, '_comp_', $datastream-id-suffix, '_', .)"/>
                            <xsl:attribute name="timestamp" select="$T"/>
                            <xsl:comment expand-text="true">This is the content from «{resolve-uri(., $base)}»</xsl:comment>
                            <xsl:copy-of select="doc(.)"/>
                        </xsl:element>
                    </xsl:for-each>
                </xsl:for-each>
            </xsl:if>
        </xsl:element>
    </xsl:template>
    <xsl:template mode="selective-copy" match="metadata" xpath-default-namespace="http://oval.mitre.org/XMLSchema/oval-definitions-5">
        <xsl:copy copy-namespaces="no">
            <xsl:apply-templates mode="selective-copy" select="attribute::node()"/>
            <xsl:copy-of select="element()" copy-namespaces="no"/>
            <xsl:choose>
                <xsl:when test="not(reference)">
                    <xsl:variable name="file" as="xs:string" select="tokenize(base-uri(), '/')[last()]"/>
                    <xsl:for-each select="$XCCDF//Rule[descendant::check-content-ref[matches(@href, $file)]]" xpath-default-namespace="http://checklists.nist.gov/xccdf/1.2">
                        <xsl:for-each select="ident[@system = 'http://cce.mitre.org/']">
                            <xsl:element name="reference" namespace="http://oval.mitre.org/XMLSchema/oval-definitions-5">
                                <xsl:attribute name="source" select="'http://cce.mitre.org'"/>
                                <xsl:attribute name="ref_id" select="."/>
                            </xsl:element>
                        </xsl:for-each>
                    </xsl:for-each>
                </xsl:when>
            </xsl:choose>
        </xsl:copy>
    </xsl:template>
    <xsl:template mode="selective-copy" match="attribute::node()">
        <xsl:copy-of select="."/>
    </xsl:template>
    <xsl:template mode="selective-copy" match="*">
        <xsl:copy copy-namespaces="no">
            <xsl:apply-templates mode="selective-copy" select="attribute::node()"/>
            <xsl:apply-templates mode="selective-copy"/>
        </xsl:copy>
    </xsl:template>
</xsl:stylesheet>
