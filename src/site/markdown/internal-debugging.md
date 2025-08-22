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
the library itself.

There are several ways to activate internal debug logging:
-# Setting the environment variable <code>LOG4CXX_DEBUG</code> to the value <code>true</code>
-# If using a properties file, add the line <code>log4j.debug=true</code> to your file
-# If using an XML file, add the <code>debug="true"</code> attribute in the <code>log4j.configuration</code> element
-# Configure the library programmatically by calling
[LogLog::setInternalDebugging](@ref log4cxx.helpers.LogLog.setInternalDebugging)

To disable all messages, including error and warning messages,
call [LogLog::setQuietMode(true)](@ref log4cxx.helpers.LogLog.setQuietMode).

All Log4cxx internal logging messages are sent to stderr,
with each line prefixed by <code>log4cxx:</code>.
