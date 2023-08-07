Qt Support {#qt-support}
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

When using Qt, messages from the Qt framework itself or other libraries
may use the `QDebug` classes.  By default, this will print to stderr,
thus bypassing the logger entirely.  In order to have these messages
routed to Log4cxx, a message handler for Qt must be installed.

Log4cxx provides a cmake build option `LOG4CXX_QT_SUPPORT=ON`
which adds the log4cxx::qt namespace methods
for directing Qt messages to Log4cxx and
using the Qt event loop to process a configuration file change.
Use the target `log4cxx-qt` instead of `log4cxx`
in your `target_link_libraries` cmake directive.
Also, including `log4cxx-qt/logger.h` allows you to use QString values
in the LOG4CXX_WARN, LOG4CXX_INFO, LOG4CXX_DEBUG etc. macros.

To install a message handler that will route the Qt logging messages
through Log4cxx, include the messagehandler.h and call
`qInstallMessageHandler` as follows:

```cpp
#include <log4cxx-qt/messagehandler.h>

...

qInstallMessageHandler( log4cxx::qt::messageHandler );
```

Note that by default, this message handler also calls `abort` upon a
fatal message.

For how to use the Qt event loop to monitor the configuration file,
see the \ref com/foo/config-qt.h and \ref com/foo/config-qt.cpp example files.

Note that when using the above technique
you *must* configure Log4cxx after creating your QCoreApplication instance
(see the \ref MyApp-qt.cpp file for an example of this).

\example MyApp-qt.cpp
This file is an example of how to configure Log4cxx in a Qt application.

\example com/foo/config-qt.h
This header file is for Log4cxx configuration in a Qt application.

\example com/foo/config-qt.cpp
This file is an example of how to use the Qt event loop to monitor the Log4cxx configuration file.

