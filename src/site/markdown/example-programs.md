Quick Start {#quick-start}
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
[TOC]

Creating useful log information requires a fair amount
of planning and effort. Observation shows that approximately 4 percent
of code is dedicated to logging. Consequently, even moderately sized
applications will have thousands of logging statements embedded within
their code. Given their number, it becomes imperative to manage these
log statements without the need to modify them manually.

Let us give a taste of how this is done with the help of an imaginary
application *MyApp* that uses Log4cxx.

# A Simple Example {#example1}

In order to start using Log4cxx, a simple example program is shown below.
This program does nothing useful, but it shows the basics of how to start using Log4cxx.
Using the [BasicConfigurator](@ref log4cxx.BasicConfigurator) class, we are able to quickly configure the library
to output DEBUG, INFO, etc level messages to standard output.
\include MyApp1.cpp

The above application does nothing useful except to show how to initialize logging
with the BasicConfigurator and do logging with different loggers.
Note that file based configurations are also possible -
see [DOMConfigurator](@ref log4cxx.xml.DOMConfigurator.configure)
and [PropertyConfigurator](@ref log4cxx.PropertyConfigurator.configure).

Configuring Log4cxx in the main function has the limitation that
any logging statements in static initialization code will not generate output.
Log4cxx must be configured before it is used and
in this example Log4cxx is not configured until the main() function starts.

# A Less Simple Example {#example2}

In this example we use a *getLogger()* wrapper function
which configures Log4cxx on the first usage.
The advantages of this approach are:

- Log4cxx configuration can be reused in multiple applications.
- The structure exhibits better [separation of concerns](https://en.wikipedia.org/wiki/Separation_of_concerns).
- Log statements in static initialization code will generate output.

This program (*MyApp*) begins by including the file
that defines the com::foo::getLogger() function.
It obtains a logger named *MyApp*
(which in this example is the fully qualified name)
from the com::foo::getLogger() function.

*MyApp* uses the *com::foo::Bar* class defined in header file *com/foo/bar.h*.
\include MyApp2.cpp

The *com::foo::Bar* class is defined in header file *com/foo/bar.h*.
\include com/foo/bar.h

The *com::foo::Bar* class is implemented in the file *com/foo/bar.cpp*.
\include com/foo/bar.cpp

The header file \ref com/foo/config.h defines the com::foo::getLogger() function
and a *LoggerPtr* type for convenience.


The file \ref com/foo/config1.cpp implements the com::foo::getLogger() function
defines *initAndShutdown* as a *static struct* so its constructor
is invoked on the first call to the com::foo::getLogger() function
and its destructor is automatically called during application exit.

The invocation of the
[BasicConfigurator::configure](@ref log4cxx.BasicConfigurator.configure)
method creates a rather simple Log4cxx setup. This method is hardwired
to add to the root logger a [ConsoleAppender](@ref log4cxx.ConsoleAppender).
The output will be formatted using a
[PatternLayout](@ref log4cxx.PatternLayout)
set to the pattern `%%r [%%t] %%p %%c %%x - %%m%%n`.

Note that by default, the root logger is assigned a *DEBUG* level.

The output of MyApp is:

~~~
    0 [12345] INFO MyApp null - Entering application.
    0 [12345] DEBUG com.foo.Bar null - Did it again!
    0 [12345] INFO MyApp null - Exiting application.
~~~

# Runtime Configuration {#configuration}

The Log4cxx environment is fully configurable programmatically. However,
it is far more flexible to configure Log4cxx using configuration files.
Currently, configuration files can be written in XML or in Java
properties (key=value) format.

The previous example always outputs the same log information.
Fortunately, it is easy to modify *config.cpp* so that the log output can be
controlled at runtime. Here is a slightly modified version.
\include com/foo/config2.cpp

This version of *config.cpp* instructs [PropertyConfigurator](@ref log4cxx.PropertyConfigurator.configure)
to use the *MyApp.properties* file to configure Log4cxx.
A more realistic approach would (for example)
use the current module name to select the configuration file
(see the \ref com/foo/config3.cpp file for how to do this).

Here is a sample *MyApp.properties* configuration file that results in exactly same output
as the previous [BasicConfigurator::configure](@ref log4cxx.BasicConfigurator.configure) based example.

~~~
    # Set root logger level to DEBUG and its only appender to A1.
    log4j.rootLogger=DEBUG, A1

    # A1 is set to be a ConsoleAppender.
    log4j.appender.A1=org.apache.log4j.ConsoleAppender

    # A1 uses PatternLayout.
    log4j.appender.A1.layout=org.apache.log4j.PatternLayout
    log4j.appender.A1.layout.ConversionPattern=%r [%t] %-5p %c %x - %m%n
~~~

It can be noticed that the PropertyConfigurator file format is the same
as log4j.

Suppose we are no longer interested in seeing the output of any
component belonging to the *com::foo* package. The following
configuration file shows one possible way of achieving this.

~~~
    log4j.rootLogger=DEBUG, A1
    log4j.appender.A1=org.apache.log4j.ConsoleAppender
    log4j.appender.A1.layout=org.apache.log4j.PatternLayout

    # Print the date in ISO 8601 format
    log4j.appender.A1.layout.ConversionPattern=%d [%t] %-5p %c - %m%n

    # Print only messages of level WARN or above in the package com.foo.
    log4j.logger.com.foo=WARN
~~~

The output of *MyApp* configured with this file is shown below.

~~~
    2022-12-13 11:01:45,091 [12345] INFO  MyApp - Entering application.
    2022-12-13 11:01:45,091 [12345] INFO  MyApp - Exiting application.
~~~

As the logger *com.foo.Bar* does not have an assigned level, it inherits
its level from *com.foo*, which was set to WARN in the configuration
file. The log statement from the *Bar::doIt* method has the level *DEBUG*,
lower than the logger level WARN. Consequently, *doIt()* method's log
request is suppressed.

Here is another configuration file that uses multiple appenders.
\include MyApp.properties

Calling the enhanced MyApp with the this configuration file will output
the following on the console.

~~~
     INFO [12345] (MyApp.cpp:8) - Entering application.
    DEBUG [12345] (bar.cpp:8) - Did it again!
     INFO [12345] (MyApp.cpp:11) - Exiting application.
~~~

In addition, as the root logger has been allocated a second appender,
output will also be directed to the *example.log* file. This file will
be rolled over when it reaches 100KB. When roll-over occurs, the old
version of *example.log* is automatically moved to *example.log.1*.

Note that to obtain these different logging behaviors we did not need to
recompile code. We could just as easily have logged to a UNIX Syslog
daemon, redirected all *com.foo* output to an NT Event logger, or
forwarded logging events to a remote Log4cxx server, which would log
according to local server policy, for example by forwarding the log
event to a second Log4cxx server.

\example com/foo/config.h
This header file is for encapsulating Log4cxx configuration.

\example com/foo/config1.cpp
This file is a simplified example of encapsulated Log4cxx configuration.

\example com/foo/config3.cpp
This file is an example of how to use the current module name to select the Log4cxx configuration file.
