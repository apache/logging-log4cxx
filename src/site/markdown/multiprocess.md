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

Log4cxx supports multiple processes logging the same file,
providing you do <b>not</b> set the "Append" option
to "false" (see log4cxx::FileAppender::setOption).

When the "Append" option is "true",
each logging event (or buffered set of logging events)
will be separate and contiguous in the log file.
This is achieved by using "apr_file_write" which
implements an OS dependent lock/write/unlock sequence
during which the file pointer is moved the end of the file.

To coordinate rollover across multiple applications
Log4cxx provides the log4cxx::rolling::MultiprocessRollingFileAppender.
This appender ensure that only one of the Log4cxx using processes
performs the rollover process when the log file
reaches its size limit.

Coordinating with other processes adds significant overhead compared to log4cxx::rolling::RollingFileAppender.
Benchmark measurements show the overhead of this appender is more than 3 and 10 times
the overhead of log4cxx::rolling::RollingFileAppender on Linux and Windows respectively.
This overhead can be moved to a background thread by attaching the MultiprocessRollingFileAppender
to an log4cxx::AsyncAppender.

This is an optional feature, and thus must be explicitly enabled
by defining LOG4CXX_MULTIPROCESS_ROLLING_FILE_APPENDER=on when building Log4cxx.

