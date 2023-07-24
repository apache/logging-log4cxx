Logging With Multiple Processes {#multiprocess-logging}
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

If you have multiple applications that all log to the same file, it is often
desirable that the file that these applications write to will roll over when
required.  In order for that to happen, Log4cxx provides the
log4cxx::rolling::MultiprocessRollingFileAppender that will check the size of the file when
writing to the file and roll it over appropriately.

This is an optional feature, and thus must be explicitly enabled when building
Log4cxx.  This feature is also only supported on Linux at the moment.
Because this feature is non-standard, it may not work properly in all
circumstances.

