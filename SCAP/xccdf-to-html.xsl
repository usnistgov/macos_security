<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl" xmlns:xs="http://www.w3.org/2001/XMLSchema" exclude-result-prefixes="xs xd xccdf"
    version="3.0" xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" xmlns="http://www.w3.org/1999/xhtml" xpath-default-namespace="http://checklists.nist.gov/xccdf/1.2">
    <!--<xsl:output method="xhtml"/>-->
    <xsl:output encoding="UTF-8"/>
    <xsl:output indent="no"/>
    <xsl:strip-space elements="*"/>
    <xsl:variable name="UTC" as="xs:duration" select="xs:dayTimeDuration('PT0H')"/>
    <xsl:variable name="UTC-date" select="adjust-date-to-timezone(current-date(), $UTC)"/>
    <xsl:variable name="UTC-datetime" select="adjust-dateTime-to-timezone(current-dateTime(), $UTC)"/>
    <xsl:template match="Benchmark">
        <xsl:text disable-output-escaping="yes">&lt;!DOCTYPE html></xsl:text>
        <html xmlns="http://www.w3.org/1999/xhtml">
            <xsl:copy-of select="attribute::xml:lang"/>
            <head>
                <title>
                    <xsl:value-of select="title"/>
                </title>
                <link type="text/css" href="XCCDF.css"/>
                <style type="text/css">
                    body {
                        font-family: Ubuntu, Arial, 'Liberation Sans', 'DejaVu Sans', sans-serif;
                    }
                    mark,
                    code,
                    command {
                        font-family: 'Ubuntu Monospace', Consolas, Menlo, Monaco, 'Lucida Console', 'Liberation Mono', 'DejaVu Sans Mono', 'Bitstream Vera Sans Mono', 'Courier New', monospace, serif;
                    }
                    code {
                        background: #eeeeee;
                    }
                    command {
                        background: #eeeeee;
                    }
                    pre {
                        overflow: auto;
                    }
                    .title {
                        font-style: italic;
                    }
                    .warning {
                        font-weight: bold;
                        background-color: #fcf8e3;
                        border-color: #faebcc;
                    }
                    td.icon {
                        text-align: center;
                    }
                    span.icon {
                        font-weight: bold;
                        font-size: large;
                    }
                    table {
                        background-color: white;
                        color: black;
                        margin-top: 1em;
                        border-spacing: 2px;
                        font-size: smaller;
                    }
                    .smaller {
                        font-size: smaller;
                    }
                    .operator {
                        font-weight: bold;
                    }</style>
                <style>
                    table {
                        background-color: white;
                        color: black;
                        margin-top: 1em;
                        border-spacing: 2px;
                        font-size: smaller;
                    }
                    
                    table table {
                    
                        font-size: 105%;
                    
                    }
                    
                    caption {
                        font-size: larger;
                        font-weight: bold;
                        background-color: #d0d0d0;
                        color: inherit;
                        margin-top: 1em;
                    }
                    
                    
                    thead tr {
                        background-color: #e0e0e0;
                        color: inherit;
                    }
                    
                    thead th {
                        vertical-align: bottom;
                        white-space: normal;
                    }
                    
                    thead td {
                    }
                    
                    tbody tr {
                        vertical-align: top;
                    }
                    
                    tbody th {
                        text-align: left;
                        background-color: #e8e8e8;
                        color: inherit;
                    }
                    
                    tbody tr {
                        background-color: #f0f0f0;
                        color: inherit;
                    }
                    tbody tr.odd-row {
                        background-color: #f0f0ff;
                        color: inherit;
                    }
                    
                    tbody td {
                    }
                    
                    
                    tbody td.selected {
                        text-align: center;
                    }
                    
                    col.col_group {
                        width: auto;
                    }
                    col.col_rule {
                        width: auto;
                    }
                    col.col_selected {
                        width: 7em;
                    }
                    
                    tbody th.selected {
                        text-align: center;
                        color: inherit;
                    }</style>
            </head>
            <body>
                <h1>
                    <xsl:value-of select="title"/>
                </h1>
                <p>
                    <xsl:text expand-text="true">This report prepared {$UTC-datetime}.</xsl:text>
                </p>
                <div>ID: <code>
                        <xsl:value-of select="@id"/>
                    </code>
                </div>
                <p>
                    <xsl:text expand-text="true">Version: {version}, {version/@time}</xsl:text>
                    <xsl:choose>
                        <xsl:when test="version/@update and matches(version/@update, '^(http|https)://')">
                            <xsl:text expand-text="true">, updates are available from </xsl:text>
                            <a href="{version/@update}" title="Link to source of updates for this checklist">
                                <xsl:value-of select="version/@update"/>
                            </a>
                        </xsl:when>
                        <xsl:when test="version/@update">
                            <xsl:text expand-text="true">, updates are available from </xsl:text>
                            <xsl:value-of select="version/@update"/>
                        </xsl:when>
                    </xsl:choose>
                </p>
                <p>
                    <xsl:text>Status: </xsl:text>
                    <em>
                        <xsl:value-of select="status"/>
                    </em>
                    <xsl:text expand-text="true"> ({status/@date})</xsl:text>
                </p>
                <p>
                    <xsl:text>Description: </xsl:text>
                    <xsl:value-of select="description/child::node()"/>
                </p>
                <p>
                    <xsl:text expand-text="true">There are {count(//Rule)} rules. {count(//Rule[not(descendant::check[@system='http://oval.mitre.org/XMLSchema/oval-definitions-5'])])} lack an OVAL definition.</xsl:text>
                </p>
                <p>There are <xsl:value-of select="count(//Profile)"/> profiles: </p>
                <ul>
                    <xsl:for-each select="//Profile">
                        <li>
                            <code>
                                <span>
                                    <xsl:value-of select="@id"/>
                                </span>
                            </code>
                            <xsl:text expand-text="true"> ({count(select[@selected cast as xs:boolean])} rules)</xsl:text>
                            <div>
                                <xsl:text>Title: </xsl:text>
                                <span class="title">
                                    <xsl:value-of select="title"/>
                                </span>
                            </div>
                            <div>
                                <xsl:copy-of select="description/child::node()"/>
                            </div>
                            <xsl:if test="@extends">
                                <div>
                                    <xsl:text> Extends </xsl:text>
                                    <xsl:value-of select="//Profile[@id = current()/@extends]/title"/>
                                    <xsl:text>.</xsl:text>
                                </div>
                            </xsl:if>
                        </li>
                    </xsl:for-each>
                </ul>
                <h2>Groups, Rules</h2>
                <p>
                    <xsl:choose>
                        <xsl:when test="//Rule[@selected cast as xs:boolean]">
                            <xsl:text>Some rules are selected by default (are active unless specifically deselected by a Profile).</xsl:text>
                        </xsl:when>
                        <xsl:otherwise>
                            <xsl:text>No rules are selected by default (must be selected in a Profile to be active).</xsl:text>
                        </xsl:otherwise>
                    </xsl:choose>
                </p>
                <table>
                    <thead>
                        <tr>
                            <th rowspan="2">Group</th>
                            <th colspan="{count(//Profile)}">Profiles<br/>A <span class="icon">✓</span> indicates the rule is selected in the profile</th>
                            <th rowspan="2">Rule</th>
                            <th rowspan="2">OVAL</th>
                        </tr>
                        <tr>
                            <xsl:for-each select="//Profile">
                                <th>
                                    <xsl:value-of select="title"/>
                                </th>
                            </xsl:for-each>
                        </tr>
                    </thead>
                    <tbody>
                        <xsl:apply-templates mode="index" select="//Rule"/>
                    </tbody>
                </table>
                <h2>Rule Details</h2>
                <xsl:apply-templates/>
            </body>
        </html>
    </xsl:template>
    <xsl:template mode="index" match="Rule">
        <tr>
            <xsl:variable name="rule" as="element()" select="current()"/>
            <xsl:if test="generate-id() = generate-id(parent::Group/Rule[1])">
                <!--<xsl:message>
                    <xsl:value-of select="parent::Group/title"/>
                </xsl:message>-->
                <td rowspan="{count(parent::Group/Rule)}">
                    <xsl:value-of select="parent::Group/title"/>
                </td>
            </xsl:if>
            <xsl:for-each select="//Profile">
                <xsl:choose>
                    <xsl:when test="select[@idref = $rule/@id and @selected cast as xs:boolean]">
                        <td class="icon">✓</td>
                    </xsl:when>
                    <xsl:otherwise>
                        <td class="icon">⬦</td>
                    </xsl:otherwise>
                </xsl:choose>
            </xsl:for-each>
            <td>
                <div>
                    <a href="#{@id}">
                        <code>
                            <xsl:value-of select="@id"/>
                        </code>
                    </a>
                </div>
                <div class="title smaller">
                    <xsl:value-of select="title"/>
                </div>
                <xsl:choose>
                    <!--<xsl:when test="@role = 'unchecked'">
                        <div class="smaller">
                            <xsl:text>This rule is not checked!</xsl:text>
                        </div>
                    </xsl:when>-->
                    <xsl:when test="@role = 'unscored'">
                        <div class="smaller">
                            <xsl:text>This rule is not scored!</xsl:text>
                        </div>
                    </xsl:when>
                </xsl:choose>
            </td>
            <td>
                <xsl:choose>
                    <xsl:when test="@role = 'unchecked'">
                        <div>
                            <xsl:text>This rule is not checked!</xsl:text>
                        </div>
                    </xsl:when>
                    <xsl:when test="complex-check">
                        <div>
                            <xsl:for-each select="complex-check/check[@system = 'http://oval.mitre.org/XMLSchema/oval-definitions-5']">
                                <xsl:if test="position() != 1">
                                    <!--<xsl:value-of select="parent::complex-check/@operator"/>-->
                                    <span class="operator">
                                        <xsl:text> ∧ </xsl:text>
                                    </span>
                                </xsl:if>
                                <xsl:value-of select="check-content-ref/@name"/>
                            </xsl:for-each>
                        </div>
                    </xsl:when>
                    <xsl:when test="check">
                        <div>
                            <xsl:value-of select="check/check-content-ref/@name"/>
                        </div>
                    </xsl:when>
                    <xsl:otherwise>
                        <div>
                            <xsl:text>(Lacks OVAL)</xsl:text>
                        </div>
                    </xsl:otherwise>
                </xsl:choose>
            </td>
        </tr>
    </xsl:template>
    <xsl:template match="Rule">
        <h3>
            <xsl:attribute name="id">
                <xsl:value-of select="@id"/>
            </xsl:attribute>
            <xsl:value-of select="title"/>
        </h3>
        <div>
            <code>
                <xsl:value-of select="@id"/>
            </code>
        </div>
        <xsl:choose>
            <xsl:when test="ident[@system = 'https://ncp.nist.gov/cce']">
                <p>
                    <code>
                        <xsl:value-of select="ident[@system = 'https://ncp.nist.gov/cce']"/>
                    </code>
                </p>
            </xsl:when>
            <xsl:otherwise>
                <p>
                    <mark>Lacks CCE.</mark>
                </p>
            </xsl:otherwise>
        </xsl:choose>
        <p>
            <xsl:if test="not(@selected cast as xs:boolean)">
                <xsl:text>Not selected by default. </xsl:text>
            </xsl:if>
            <xsl:variable name="p" as="xs:string*" select="//Profile[select[@idref = current()/@id][@selected cast as xs:boolean]]/title"/>
            <xsl:choose>
                <xsl:when test="count($p) != 0">
                    <xsl:text expand-text="true">Selected by profile {string-join($p,', ')}.</xsl:text>
                </xsl:when>
                <xsl:otherwise>
                    <xsl:text>Not selected in any profile.</xsl:text>
                </xsl:otherwise>
            </xsl:choose>
        </p>
        <xsl:choose>
            <xsl:when test="@role = 'unchecked'">
                <p>
                    <xsl:text>This rule is not checked!</xsl:text>
                </p>
            </xsl:when>
            <xsl:when test="@role = 'unscored'">
                <p>
                    <xsl:text>This rule is not scored!</xsl:text>
                </p>
            </xsl:when>
        </xsl:choose>
        <p>
            <xsl:copy-of select="description/child::node()"/>
        </p>
        <xsl:if test="warning">
            <div class="warning">Warning: <div><xsl:copy-of select="warning/node()"/></div>
            </div>
        </xsl:if>
        <xsl:apply-templates/>
    </xsl:template>
    <xsl:template match="reference">
        <div>
            <xsl:text>Reference: </xsl:text>
            <xsl:choose>
                <xsl:when test="text()">
                    <a href="{@href}" target="_blank">
                        <xsl:value-of select="."/>
                    </a>
                </xsl:when>
                <xsl:otherwise>
                    <a href="{@href}" target="_blank">
                        <xsl:value-of select="@href"/>
                    </a>
                </xsl:otherwise>
            </xsl:choose>
        </div>
    </xsl:template>
    <xsl:template match="fixtext">
        <div>
            <xsl:copy-of select="child::node()"/>
        </div>
    </xsl:template>
    <xsl:template match="rationale">
        <div>
            <xsl:copy-of select="child::node()"/>
        </div>
    </xsl:template>
    <xsl:template match="fix">
        <div>
            <xsl:text>Command</xsl:text>
            <xsl:if test="@reboot = 'true'">
                <xsl:text> (requires reboot ➜) </xsl:text>
            </xsl:if>
            <xsl:text>: </xsl:text>
            <code>
                <xsl:value-of select="."/>
            </code>
        </div>
    </xsl:template>
    <xsl:template match="node()" priority="-1">
        <xsl:apply-templates/>
    </xsl:template>
</xsl:stylesheet>
