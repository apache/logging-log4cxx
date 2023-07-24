Nested Diagnostic Contexts {#nested-diagnostic-contexts}
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

Most real-world systems have to deal with multiple clients
simultaneously. In a typical multithreaded implementation of such a
system, different threads will handle different clients. Logging is
especially well suited to trace and debug complex distributed
applications. A common approach to differentiate the logging output of
one client from another is to instantiate a new separate logger for each
client. This promotes the proliferation of loggers and increases the
management overhead of logging.

A lighter technique is to uniquely stamp each log request initiated from
the same client interaction. Neil Harrison described this method in the
book "Patterns for Logging Diagnostic Messages," in *Pattern Languages
of Program Design 3*, edited by R. Martin, D. Riehle, and F. Buschmann
(Addison-Wesley, 1997).

To uniquely stamp each request, the user pushes contextual information
into the *Nested Diagnostic Context* (NDC) using the *log4cxx::NDC* class.
For an example refer to \ref trivial.cpp.
Note that all methods of the *log4cxx::NDC* class are static.

The NDC is managed per thread as a *stack* of contextual information.
Each log entry will include the entire stack
for the current thread (for better control use *log4cxx::MDC*).
The user is responsible for placing the correct information in the NDC
by using the *push* and *pop* methods at
a few well-defined points in the code. In contrast, the per-client
logger approach commands extensive changes in the code.

To illustrate this point, let us take the example of a servlet
delivering content to numerous clients. The servlet can build the NDC at
the very beginning of the request before executing other code. The
contextual information can be the client's host name and other
information inherent to the request, typically information contained in
cookies. Hence, even if the servlet is serving multiple clients
simultaneously, the logs initiated by the same code, i.e. belonging to
the same logger, can still be distinguished because each client request
will have a different NDC stack. Contrast this with the complexity of
passing a freshly instantiated logger to all code exercised during the
client's request.

Nevertheless, some sophisticated applications, such as virtual hosting
web servers, must log differently depending on the virtual host context
and also depending on the software component issuing the request. Recent
Log4cxx releases support multiple hierarchy trees. This enhancement
allows each virtual host to possess its own copy of the logger
hierarchy.

\example trivial.cpp
This example shows how to add a context string to each logging message using the NDC.
