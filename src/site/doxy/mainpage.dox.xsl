<?xml version="1.0" encoding="UTF-8" ?>
<!--
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements.  See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to You under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 -->
<xsl:stylesheet	version="2.0"
				xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
				xmlns:saxon="http://saxon.sf.net/"
				xmlns:xhtml="http://www.w3.org/1999/xhtml"
				exclude-result-prefixes="saxon xhtml">

	<!--
		We need textual output with XHTML nodes, which is only possible for methods other than text
		and without xml declaration or such.
	 -->
	<xsl:output	method="xml"
				omit-xml-declaration="yes"
				media-type="text/plain"
				indent="yes"
				encoding="UTF-8"
				saxon:indent-spaces="4"
	/>

	<xsl:template match="/">
		/*
		Licensed to the Apache Software Foundation (ASF) under one or more
		contributor license agreements.  See the NOTICE file distributed with
		this work for additional information regarding copyright ownership.
		The ASF licenses this file to You under the Apache License, Version 2.0
		(the "License"); you may not use this file except in compliance with
		the License.  You may obtain a copy of the License at

			  http://www.apache.org/licenses/LICENSE-2.0

		Unless required by applicable law or agreed to in writing, software
		distributed under the License is distributed on an "AS IS" BASIS,
		WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
		See the License for the specific language governing permissions and
		limitations under the License.
		*/

		/** @mainpage

		<xsl:apply-templates	select="//xhtml:div[@id = 'contentBox']/xhtml:div[@class = 'section']/*"
								mode="copy-no-namespaces"
		/>

		 */
	</xsl:template>

	<!-- http://stackoverflow.com/a/20001084/2055163 -->
	<xsl:template match="*" mode="copy-no-namespaces">
		<xsl:element name="{local-name()}">
			<xsl:copy-of select="@*" />
			<xsl:apply-templates	select="node()"
									mode="copy-no-namespaces"
			/>
		</xsl:element>
	</xsl:template>
 </xsl:stylesheet>