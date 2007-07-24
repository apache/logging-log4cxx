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
<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xsl:version="1.0">

   <xsl:output method="xml" indent="yes"/>

   <xsl:apply-templates select="/"/>

   <xsl:template match="/">
  <xsl:comment>

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

  </xsl:comment>
  <document>
  <properties>
    <title>Apache log4cxx</title>
  </properties>
  <body>
  
    <release version="0.10.0" date="2007-07-30" description="First Apache release">
       <xsl:apply-templates select='/rss/channel/item'>
           <xsl:sort select="substring-after(key, '-')" data-type="number"/>
       </xsl:apply-templates>
     </release>
  </body>
</document>
</xsl:template>

<xsl:template match="item">
      <action issue="{key}"><xsl:value-of select="summary"/></action>
</xsl:template>

</xsl:transform>
