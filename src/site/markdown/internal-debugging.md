Internal Debugging {#internal-debugging}
===
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

Because Log4cxx is a logging library, we can't use it to output errors from
the library itself.  There are several ways to activate internal logging:

1. Configure the library directly by calling the
[LogLog::setInternalDebugging](@ref log4cxx.helpers.LogLog.setInternalDebugging)
method
2. If using a properties file, set the value `log4j.debug=true` in your configuration file
3. If using an XML file, set the attribute `internalDebug=true` in the root node
4. From the environment: `LOG4CXX_DEBUG=true`

All error and warning messages are sent to stderr.
