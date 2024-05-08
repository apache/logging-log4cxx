Introduction {#introduction}
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

Apache Log4cxx is a logging framework for C++ patterned after [Apache log4j],
which uses [Apache Portable Runtime] for most platform-specific code and should
be usable on any platform supported by APR. Apache Log4cxx is licensed under
the [Apache License], an open source license certified by the [Open Source Initiative].

Experience indicates that almost every large application needs runtime configurable logging.
In the usual configuration, informational, warning and error log messages
are saved to a persistent medium so they are available for study at a later time.
With Log4cxx it is possible to activate additional logging output or disable some output
for one or more modules of the running application by changing the configuration file.

In the development cycle, logging can be an auditing tool.
Debugging log output can be activated for an aspect of the application
simply by modifying a configuration file.
The correctness of a function should be verified by viewing logged calculated values.
A faulty piece of code can be isolated by viewing logged function input values
and the corresponding logged result values.
These debugging log statements can be removed from the shipped application
using a compiler build directive.
Logging statements do increase the (code) size of the application,
but with Log4cxx the speed of the application is not generally affected (see [Performance]).

Logging is useful where debuggers are not, for example:
- distributed applications
- multithreaded applications
- scientific applications (with vector and matrix valued variables)
- real-time applications
- event centered (e.g. GUI) applications

For persisted messages, the storage location and the quantity retained
can be specified and changed using a configuration file.
The configuration also allows you to control the destination of log messages.
They can be sent to a file, a remote socket server, event loggers as well as the console,
with support for directing particular messages to one or more destinations.

The [example programs page] will let you to quickly start using Log4cxx.
The components of Log4cxx are described on the [concepts page].
For a more general overview, the logging services committee
provides a [logging overview page] that explains more of what logging is and
when to use it.

[Apache log4j]:https://logging.apache.org/log4j/2.x/
[Apache Portable Runtime]:https://apr.apache.org/
[Apache License]:https://www.apache.org/licenses/
[example programs page]:quick-start.html
[concepts page]:concepts.html
[Open Source Initiative]:https://opensource.org/
[Performance]:performance.html
[logging overview page]:https://logging.apache.org/what-is-logging.html
