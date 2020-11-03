<?xml version="1.0" encoding="UTF-8"?>
<sch:schema xmlns:sch="http://purl.oclc.org/dsdl/schematron" queryBinding="xslt2" xmlns:sqf="http://www.schematron-quickfix.com/validator/process"
    see="https://csrc.nist.gov/projects/security-content-automation-protocol/scap-releases/scap-1-3">
    <sch:title>This Schematron document asserts rules which are either mandatory or recommended by NIST SP 800-126 revision 3 as well as other normative documnents incorporated by
        reference</sch:title>
    <!-- NB: the SCAP 1.3 namespace ends in 1.2. Go figure. -->
    <sch:ns prefix="ds" uri="http://scap.nist.gov/schema/scap/source/1.2"/>
    <sch:ns prefix="xccdf" uri="http://checklists.nist.gov/xccdf/1.2"/>
    <sch:ns prefix="cpe2" uri="http://cpe.mitre.org/language/2.0"/>
    <sch:ns prefix="cpe2-dict" uri="http://cpe.mitre.org/dictionary/2.0"/>
    <sch:ns prefix="cpe2-dict-ext" uri="http://scap.nist.gov/schema/cpe-extension/2.3"/>
    <sch:ns prefix="xhtml" uri="http://www.w3.org/1999/xhtml"/>
    <sch:ns prefix="dc" uri="http://purl.org/dc/elements/1.1/"/>
    <sch:ns prefix="dsig" uri="http://www.w3.org/2000/09/xmldsig#"/>
    <sch:ns prefix="oval-def" uri="http://oval.mitre.org/XMLSchema/oval-definitions-5"/>
    <sch:ns prefix="oval" uri="http://oval.mitre.org/XMLSchema/oval-common-5"/>
    <sch:pattern see="https://csrc.nist.gov/publications/detail/sp/800-126/rev-3/final">
        <sch:title>SCAP data stream constraints</sch:title>
        <sch:rule context="ds:data-stream-collection">
            <sch:assert test="@schematron-version = '1.3'">&lt;<sch:name/>&gt; must have @schematron-version set to "1.3" (since SCAP 1.3 conmtent must be validated using SCAP 1.3 schemata).</sch:assert>
        </sch:rule>
        <sch:rule context="ds:data-stream">
            <sch:assert test="@scap-version = '1.3'">&lt;<sch:name/>&gt; SHALL have @scap-version set to "1.3". See NIST SP 800-126 Revision 3 §3.1.1 Table 3.</sch:assert>
        </sch:rule>
        <sch:rule context="cpe2-dict:cpe-list/cpe2-dict:cpe-item">
            <!-- See NIST Interagency Reports 7695, 7696, 7697, 7698 for CPE 2.3 -->
            <!-- Which is quite perverse -->
            <!-- The only way to conform to NISTIR 7275 is to use a <cpe23-item> element within a <cpe-item> element -->
            <!-- and that <cpe-item> element is *required* to use an deprecated/despised CPE 2.2 @name -->
            <sch:assert test="cpe2-dict-ext:cpe23-item" see="https://csrc.nist.gov/CSRC/media/Publications/nistir/7275/rev-4/final/documents/nistir-7275r4_updated-march-2012_clean.pdf"
                    >&lt;<sch:value-of select="name(.)"/>&gt; missing a &lt;cpe23-item&gt;. See NISTIR 7275 Revision 4 §6.2.5 ¶3.</sch:assert>
            <!-- So, no cpe23-item means XCCDF document cannot address a CPE 2.3 dictionary construct (and be conformant) -->
            <!-- See as well NISTIR 7275 -->
        </sch:rule>
    </sch:pattern>
    <sch:pattern see="https://csrc.nist.gov/publications/detail/nistir/7275/rev-4/final">
        <sch:title>XCCDF constraints</sch:title>
        <sch:rule context="xccdf:Benchmark" see="https://csrc.nist.gov/publications/detail/sp/800-126/rev-3/final">
            <sch:assert flag="WARNING" test="@style = 'SCAP_1.3'">Warning: &lt;<sch:name/> style="<sch:value-of select="@style"/>"&gt; SHOULD have the value <sch:emph>SCAP_1.3</sch:emph>. See NIST SP
                800-126 Revision 3 §3.2.2 ¶1 item 4.</sch:assert>
        </sch:rule>
        <sch:rule context="xccdf:Benchmark" see="https://csrc.nist.gov/publications/detail/sp/800-126/rev-3/final">
            <sch:assert test="@xml:lang">The element &lt;<sch:name/>&gt; SHALL have an @xml:lang attribute. See NIST SP 800-126 Revision 3 §3.2.2 ¶1 item 3.</sch:assert>
        </sch:rule>
        <sch:rule context="xccdf:version" see="https://csrc.nist.gov/publications/detail/sp/800-126/rev-3/final">
            <sch:assert flag="WARNING" test="@time">Warning: the @time attribute of the &lt;<sch:name/>&gt; element SHOULD be used for a timestamp of when the benchmark was defined. See NIST SP
                800-126 Revision 3 §3.2.2 ¶1 item 1a.</sch:assert>
        </sch:rule>
        <sch:rule context="xccdf:version" see="https://csrc.nist.gov/publications/detail/sp/800-126/rev-3/final">
            <sch:assert flag="WARNING" test="@update">Warning: the @update attribute of the &lt;<sch:name/>&gt; element SHOULD be used for a URI that specifies where updates to the benchmark can be
                obtained. See NIST SP 800-126 Revision 3 §3.2.2 ¶1 item 2.</sch:assert>
        </sch:rule>
        <sch:rule context="xccdf:Benchmark/xccdf:platform" see="https://csrc.nist.gov/CSRC/media/Publications/nistir/7275/rev-4/final/documents/nistir-7275r4_updated-march-2012_clean.pdf">
            <sch:assert test="starts-with(@idref, 'cpe:2.3')">&lt;<sch:name/> idref="<sch:value-of select="@idref"/>"&gt; is not a CPE 2.3 formatted string binding. See NISTIR 7275 Revision 4 §6.2.5
                ¶3.</sch:assert>
            <!--
                Read the following and decide what SHALL, or MAY, or SHALL⨯MAY⨯SHOULD⨯MAY convey.
                
                "Within XCCDF documents, all CPE names SHALL comply with the CPE 2.3 Naming specification
                [IR7695], and all CPE applicability language expressions SHALL comply with the CPE 2.3 Applicability
                Language specification [IR7698]. CPE 2.0 names MAY be used for backwards compatibility, but their
                use has been deprecated for XCCDF 1.2. All CPE 2.3 names and applicability language expressions in
                XCCDF documents SHOULD use formatted string bindings but MAY use URI bindings instead, both as
                defined in [IR7695]." 
            -->
        </sch:rule>
        <sch:rule context="xccdf:Rule/xccdf:platform" see="https://csrc.nist.gov/CSRC/media/Publications/nistir/7275/rev-4/final/documents/nistir-7275r4_updated-march-2012_clean.pdf">
            <sch:assert test="starts-with(@idref, 'cpe:2.3')">&lt;<sch:name/> idref="<sch:value-of select="@idref"/>"&gt; is not a CPE 2.3 formatted string binding. See NISTIR 7275 Revision 4 §6.2.5
                ¶3.</sch:assert>
        </sch:rule>
    </sch:pattern>
    <sch:pattern>
        <sch:title>OVAL constraints</sch:title>
        <sch:rule context="oval:schema_version" see="https://doi.org/10.6028/NIST.SP.800-126A">
            <sch:assert flag="WARNING" test=". = '5.11.2'">Warning: &lt;<sch:name/>&gt;<sch:value-of select="."/>&lt;/<sch:name/>&gt; should be 5.11.2. See NIST SP 800-126A §2.2.</sch:assert>
        </sch:rule>
    </sch:pattern>
</sch:schema>
