Threading {#threading}
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
# Threading Notes with Log4cxx

Log4cxx is designed to be thread-safe under under normal usage.  This
means that logging itself is always thread-safe, however there are
certain circumstances that can cause threading issues with Log4cxx.

## Unexpected Exit

In multithreaded applications, it is possible to call `exit()` from any
thread in the application.  When this happens, other threads in the
application may continue to run and attempt to log information.  As of
version 12 of Log4cxx, this should not cause the library to crash.

We recommend that a graceful exit be performed whenever possible, and that
all threads be terminated properly before returning from `main()`.

See [LOGCXX-322][3] for more information.

## Threads Created by Log4cxx

Under certain configurations, Log4cxx may create new threads in order to do
tasks(e.g. network comms, other async operations).  On Linux systems, this
can lead to undesirable signal delivery, as signals can be delivered to
any thread in the process.

To handle signals properly on Linux, you may wish to utilize the [signalfd][1]
API to handle signals correctly.  Another way of handling signals is to
create a pipe internal to your application to notify the main loop that there
is a signal available - see the [Qt documentation][2] for more information.

Log4cxx provides a mechanism for defining methods to be called at two main
points in the lifecycle of a thread:

1. Just before the thread starts
2. Just after the thread starts

These two points are intended to let client code determine how best to start
threads.  Log4cxx provides a basic implementation of these for POSIX in order
to block signals to the new threads that it creates.

Once a new thread is created, there is also a callback function that lets
client code do operations on the thread directly.  A sample method in Log4cxx
has a callback to name the thread in order to make debugging nicer.

In order to use these callback functions, use the ThreadUtility class.  You
can use some sample functions(not no-ops) as follows:

```
ThreadUtility::configureThreadFunctions( ThreadUtility::preThreadBlockSignals,
					 ThreadUtility::threadStartedNameThread,
					 ThreadUtility::postThreadUnblockSignals );
```

These sample functions will block all POSIX signals before starting a new thread,
and then unblock them once the thread has been created.  You may provide your
own functions to handle this if you so choose.


[1]: https://man7.org/linux/man-pages/man2/signalfd.2.html
[2]: https://doc.qt.io/qt-5/unix-signals.html
[3]: https://issues.apache.org/jira/browse/LOGCXX-322
