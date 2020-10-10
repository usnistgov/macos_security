<?xml version="1.0" encoding="UTF-8"?>
<!-- identity transform with excision -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" exclude-result-prefixes="xs" version="1.0">
    <!-- indent for those desirous of such -->
    <xsl:output indent="yes"/>
    <!-- death to comments -->
    <xsl:template match="comment()"/>
    <!-- death to processing-instructions -->
    <xsl:template match="processing-instruction()"/>
    <!-- identity transform -->
    <xsl:template match="node()" priority="-1">
        <xsl:copy>
            <xsl:copy-of select="attribute::node()"/>
            <xsl:apply-templates/>
        </xsl:copy>
    </xsl:template>
</xsl:stylesheet>
