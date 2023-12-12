Log Flow {#log-flow}
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

Messages are logged as follows:

1. If using the Log4cxx macros(e.g. `LOG4CXX_DEBUG`), the macro must first be
enabled.  If the macro is not enabled(for example by setting the `LOG4CXX_THRESHOLD`
macro), then the log message is not compiled in and the line of code becomes
a no-op.
2. The logger level is checked to see if the request level is enabled.  If
it is, the message is then sent to the logger.
3. The logger creates a new message and gives it to all of its appenders.
4. Each appender checks the logging event's level is greater or equal to the appender's threshold level.
5. Each appender checks its filters to see if the message should be logged.

Filters can perform the following actions:

1. Accept the message: This message will immediately be logged without
consulting any remaining filters
2. Reject the message: This message will immediately be rejected without
consulting any remaining filters
3. Neutral: This filter neither rejects nor accepts the message, it will
be passed on to the next filter in the chain

If a filter accepts the message, the message will be logged.
If no filter rejects the message, the message will be logged.

The following flow diagram shows how messages flow through the system:

![](images/log4cxx-flow.png)

