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

Log4cxx provides a separate library, log4cxx-qt, which contains useful
utilities for working with Qt.

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
