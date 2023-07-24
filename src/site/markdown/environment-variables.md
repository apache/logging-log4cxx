Environment Variables Used by Log4cxx {#environment-variables}
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

There are several environment variables that can be set in order to influence how
Log4cxx works.  They are summarized in the following table:


| Environment Variable | Usage |
| -------------------- | ----- |
| LOG4CXX\_DEBUG       | Set to the value 'true' to enable internal debugging of Log4cxx.  All output goes to stderr.  This can be useful to determine why a configuration file is not loading |
| log4j.configuratorClass | Used to determine what class to use to configure the logging system |
| LOG4CXX\_CONFIGURATOR\_CLASS | Used to determine what class to use to configure the logging system.  Takes precedence over log4j.configuratorClass |
| log4j.configuration | Set the file to load to configure the logging system |
| LOG4CXX\_CONFIGURATION | Set the file to load to configure the logging system.  Takes precedence over log4j.configuration |
| LOG4CXX\_CONFIGURATION\_WATCH\_SECONDS | Set how often the configuration file should be checked for changes |

