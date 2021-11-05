# Changes for next major version of Log4cxx
===
<!--
 Note: License header cannot be first, as doxygen does not generate
 cleanly if it before the '==='
-->
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

* Removed log4j style Java serialization.  Due to Java's inherent problems
with serialization, and the fact that Chainsaw no longer supports it, it has
been completely removed.
* Removal of TTCCLayout.  If you still want this layout, use a PatternLayout
with a format similar to the following:
`%r [%t] %-5p - %m%n`
* Removal of DateLayout.  Use PatternLayout instead.
