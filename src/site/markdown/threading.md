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
[TOC]

# Threading Notes with Log4cxx {#threading-notes}

Log4cxx is designed to be thread-safe under under normal usage.  This
means that logging itself is always thread-safe, however there are
certain circumstances that can cause threading issues with Log4cxx.

## Unexpected Exit {#unexpected-exit}

In multithreaded applications, it is possible to call `exit()` from any
thread in the application.  When this happens, other threads in the
application may continue to run and attempt to log information.  As of
version 12 of Log4cxx, this should not cause the library to crash.

We recommend that a graceful exit be performed whenever possible, and that
all threads be terminated properly before returning from `main()`.

See [LOGCXX-322][3] for more information.

## Signal Handling with Log4cxx {#signal-handling}

Under certain configurations, Log4cxx may create new threads in order to do
tasks(e.g. network comms, other async operations).  On Linux/POSIX systems,
this can lead to undesirable signal delivery, as signals can be delivered to
any thread in the process.  This can be most clearly seen if your application
uses the [sigwait(3)][4] system call, as the thread that calls sigwait may
not be the thread that actually gets the signal.  By default, Log4cxx
configures itself to block all signals to new threads that it creates on
Linux/POSIX systems.  See the [section on configuring](@ref configuring)
for more details on how to configure.

There are three main ways to handle signals coming to your process.   All
of these ways of handling signals are supported by Log4cxx in order to
provide flexibility to users of the library.  These three ways are:

1. Write to a file descriptor in a signal handler, notifying your main event
loop of a signal. If you use Qt, [their documentation][2] has information on
this method of handling a signal.
2. (Linux-only) Use [signalfd(2)][1] to create a file descriptor that notifies
you of a signal.  This is a special case of (1).
3. Block signals in newly created threads, ensuring that signals can only be
sent to threads of your choosing.

If you need to use option #3(for example, because you are using sigwait),
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

In order to use these callback functions, use the [ThreadUtility](@ref log4cxx.helpers.ThreadUtility)
class.  You can configure the ThreadUtility class in several different ways by using the
[ThreadUtility::configure](@ref log4cxx.helpers.ThreadUtility.configure)
method with several pre-defined configurations.
In the event that you need special signal handling, you can implement your own
functions, and use the [ThreadUtility::configureFuncs](@ref log4cxx.helpers.ThreadUtility.configureFuncs) method in order to
customize exactly what happens.

### Configuring Thread {#configuring}

To tell Log4cxx what to do by default when starting a new thread, the enum
[ThreadConfigurationType](@ref log4cxx.helpers.ThreadConfigurationType) may be
used to configure the library appropriately.  By default, all signals on POSIX
systems will be blocked to ensure that other threads do not get signals.

To change this default, a simple change to your configuration files may be done.

Example to disable the automatic signal blocking with XML configuration:
```
<log4j:configuration threadConfiguration="NoConfiguration">
...
</log4j:configuration>
```

Example to disable the automatic signal blocking with properties configuration:
```
log4j.threadConfiguration=NoConfiguration
```

[1]: https://man7.org/linux/man-pages/man2/signalfd.2.html
[2]: https://doc.qt.io/qt-5/unix-signals.html
[3]: https://issues.apache.org/jira/browse/LOGCXX-322
[4]: https://man7.org/linux/man-pages/man3/sigwait.3.html
