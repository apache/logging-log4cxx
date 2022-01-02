Usage {#usage}
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

# Loggers {#loggers}

Log4cxx has three main components: *loggers*, *appenders* and *layouts*.
These three types of components work together to enable developers to
log messages according to message type and level, and to control at
runtime how these messages are formatted and where they are reported. 

## Hierarchy {#hierarchy}

The first and foremost advantage of any logging API over plain
`std::cout` resides in its ability to disable certain log statements
while allowing others to print unhindered. This capability assumes that
the logging space, that is, the space of all possible logging
statements, is categorized according to some developer-chosen criteria. 

Loggers are named entities. Logger names are case-sensitive and they
follow the hierarchical naming rule: 

**Named Hierarchy** 

A logger is said to be an *ancestor* of another logger if its name
followed by a dot is a prefix of the *descendant* logger name. A logger
is said to be a *parent* of a *child* logger if there are no ancestors
between itself and the descendant logger. 

For example, the logger named `com.foo` is a parent of the logger
named `com.foo.Bar`. Similarly, `java` is a parent of `java.util`
and an ancestor of `java.util.Vector`. This naming scheme should be
familiar to most developers. 

The root logger resides at the top of the logger hierarchy. It is
exceptional in two ways: 

1.  it always exists, 
2.  it cannot be retrieved by name. 

Invoking the class static
log4cxx::Logger::getRootLogger method retrieves it. All other loggers are instantiated and retrieved
with the class static log4cxx::Logger::getLogger
method. This method takes the name of the desired logger as a parameter.
Some of the basic methods in the Logger class are listed below. 

~~~{.cpp}
    namespace log4cxx {
    	class Logger {
    		public:
    			// Creation & retrieval methods:
    			static LoggerPtr getRootLogger();
    			static LoggerPtr getLogger(const std::string& name);
    			static LoggerPtr getLogger(const std::wstring& name);
    	}
    }
     
    //
    // Use these macros instead of calling Logger methods directly.
    // Macros will handle char or wchar_t pointers or strings
    // or most right-hand side expressions of an
    // std::basic_string::operator<<.
    //
    #define LOG4CXX_TRACE(logger, expression) ...
    #define LOG4CXX_DEBUG(logger, expression) ...
    #define LOG4CXX_INFO(logger, expression) ...
    #define LOG4CXX_WARN(logger, expression) ...
    #define LOG4CXX_ERROR(logger, expression) ...
    #define LOG4CXX_FATAL(logger, expression) ...
~~~

## Levels {#levels}

Loggers *may* be assigned levels. The pre-defined levels: TRACE, DEBUG,
INFO, WARN, ERROR and FATAL are defined in the
log4cxx::Level class which provides accessor functions. 

If a given logger is not assigned a level, then it inherits one from its
closest ancestor with an assigned level. More formally: 

**Level Inheritance** 

The *inherited level* for a given logger *C*, is equal to the first
non-null level in the logger hierarchy, starting at *C* and proceeding
upwards in the hierarchy towards the *root* logger. 

To ensure that all loggers can eventually inherit a level, the root
logger always has an assigned level. 

Below are four tables with various assigned level values and the
resulting inherited levels according to the above rule. 

| Logger name | Assigned level | Inherited level |
| ----------- | -------------- | --------------- |
| root        | Proot          | Proot           |
| X           | none           | Proot           |
| X.Y         | none           | Proot           |
| X.Y.Z       | none           | Proot           |

Example 1

In example 1 above, only the root logger is assigned a level. This level
value, *Proot*, is inherited by the other loggers *X*, *X.Y* and
*X.Y.Z*. 

| Logger name | Assigned level | Inherited level |
| ----------- | -------------- | --------------- |
| root        | Proot          | Proot           |
| X           | Px             | Px              |
| X.Y         | Pxy            | Pxy             |
| X.Y.Z       | Pxyz           | Pxyz            |

Example 2

In example 2, all loggers have an assigned level value. There is no need
for level inheritence. 

| Logger name | Assigned level | Inherited level |
| ----------- | -------------- | --------------- |
| root        | Proot          | Proot           |
| X           | Px             | Px              |
| X.Y         | none           | Px              |
| X.Y.Z       | Pxyz           | Pxyz            |

Example 3

In example 3, the loggers *root*, *X* and *X.Y.Z* are assigned the
levels *Proot*, *Px* and *Pxyz* respectively. The logger *X.Y* inherits
its level value from its parent *X*. 

| Logger name | Assigned level | Inherited level |
| ----------- | -------------- | --------------- |
| root        | Proot          | Proot           |
| X           | Px             | Px              |
| X.Y         | none           | Px              |
| X.Y.Z       | none           | Px              |

Example 4

In example 4, the loggers *root* and *X* and are assigned the levels
*Proot* and *Px* respectively. The loggers *X.Y* and *X.Y.Z* inherits
their level value from their nearest parent *X* having an assigned
level. 

## Requests {#requests}

Logging requests are made by invoking a method of a logger instance,
preferrably through the use of LOG4CXX\_INFO or similar macros which
support short-circuiting if the threshold is not satisfied and use of
the insertion operator (\<\<) in the message parameter. 

~~~{.cpp}
    log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("com.foo"));
    const char* region = "World";
    LOG4CXX_INFO(logger, "Simple message text.");
    LOG4CXX_INFO(logger, "Hello, " << region);
    LOG4CXX_DEBUG(logger, L"Iteration " << i);
    LOG4CXX_DEBUG(logger, "e^10 = " << std::scientific << exp(10.0));
    //
    // Use a wchar_t first operand to force use of wchar_t based stream.
    //
    LOG4CXX_WARN(logger, L"" << i << L" is the number of the iteration.");
~~~

A logging request is said to be *enabled* if its level is higher than or
equal to the level of its logger. Otherwise, the request is said to be
*disabled*. A logger without an assigned level will inherit one from the
hierarchy. This rule is summarized below. 

**Basic Selection Rule** 

A log request of level *p* in a logger with (either assigned or
inherited, whichever is appropriate) level *q*, is enabled if *p \>= q*.

This rule is at the heart of log4cxx. It assumes that levels are
ordered. For the standard levels, we have *TRACE \< DEBUG \< INFO \<
WARN \< ERROR \< FATAL*. 

Here is an example of this rule. 

~~~{.cpp}
    // get a logger instance named "com.foo"
    log4cxx::LoggerPtr  logger(log4cxx::Logger::getLogger("com.foo"));
     
    // Now set its level. Normally you do not need to set the
    // level of a logger programmatically. This is usually done
    // in configuration files.
    logger->setLevel(log4cxx::Level::getInfo());
     
    log4cxx::LoggerPtr barlogger(log4cxx::Logger::getLogger("com.foo.Bar"));
     
    // This request is enabled, because WARN >= INFO.
    LOG4CXX_WARN(logger, "Low fuel level.");
     
    // This request is disabled, because DEBUG < INFO.
    LOG4CXX_DEBUG(logger, "Starting search for nearest gas station.");
     
    // The logger instance barlogger, named "com.foo.Bar",
    // will inherit its level from the logger named
    // "com.foo" Thus, the following request is enabled
    // because INFO >= INFO.
    LOG4CXX_INFO(barlogger. "Located nearest gas station.");
     
    // This request is disabled, because DEBUG < INFO.
    LOG4CXX_DEBUG(barlogger, "Exiting gas station search");
~~~

Calling the *getLogger* method with the same name will always return a
reference to the exact same logger object. 

For example, in 

~~~{.cpp}
    log4cxx::LoggerPtr x = log4cxx::Logger::getLogger("wombat");
    log4cxx::LoggerPtr y = log4cxx::Logger::getLogger("wombat");
~~~

*x* and *y* refer to *exactly* the same logger object. 

Thus, it is possible to configure a logger and then to retrieve the same
instance somewhere else in the code without passing around references.
In fundamental contradiction to biological parenthood, where parents
always preceed their children, log4cxx loggers can be created and
configured in any order. In particular, a "parent" logger will find and
link to its descendants even if it is instantiated after them. 

Configuration of the log4cxx environment is typically done at
application initialization. The preferred way is by reading a
configuration file. This approach will be discussed shortly. 

Log4cxx makes it easy to name loggers by *software component*. This can
be accomplished by statically instantiating a logger in each class, with
the logger name equal to the fully qualified name of the class. This is
a useful and straightforward method of defining loggers. As the log
output bears the name of the generating logger, this naming strategy
makes it easy to identify the origin of a log message. However, this is
only one possible, albeit common, strategy for naming loggers. Log4cxx
does not restrict the possible set of loggers. The developer is free to
name the loggers as desired. 

Nevertheless, naming loggers after the class where they are located
seems to be the best strategy known so far. 

# Appenders and Layouts {#appenders-and-layouts}

The ability to selectively enable or disable logging requests based on
their logger is only part of the picture. Log4cxx allows logging
requests to print to multiple destinations. In log4cxx speak, an output
destination is called an *appender*. Currently, appenders exist for the
[console](@ref log4cxx.ConsoleAppender), [files](@ref log4cxx.FileAppender),
GUI components, [remote socket](@ref log4cxx.net.SocketAppender)
servers, [NT Event Loggers](@ref log4cxx.nt.NTEventLogAppender),
and remote UNIX [Syslog](@ref log4cxx.net.SyslogAppender)
daemons. It is also possible to log
[asynchronously](@ref log4cxx.AsyncAppender).

More than one appender can be attached to a logger.

The
[addAppender](@ref log4cxx.Logger.addAppender)
method adds an appender to a given logger. *Each enabled logging
request for a given logger will be forwarded to all the appenders in
that logger as well as the appenders higher in the hierarchy.* In other
words, appenders are inherited additively from the logger hierarchy. For
example, if a console appender is added to the root logger, then all
enabled logging requests will at least print on the console. If in
addition a file appender is added to a logger, say *C*, then enabled
logging requests for *C* and *C*'s children will print on a file *and*
on the console. It is possible to override this default behavior so that
appender accumulation is no longer additive by
[setting the additivity flag](@ref log4cxx.Logger.setAdditivity) to `false`.

The rules governing appender additivity are summarized below.

**Appender Additivity** 

The output of a log statement of logger *C* will go to all the appenders
in *C* and its ancestors. This is the meaning of the term "appender
additivity". However, if an ancestor of logger *C*, say *P*, has the
additivity flag set to *false*, then *C*'s output will be directed to
all the appenders in *C* and it's ancestors up to and including *P* but,
not the appenders in any of the ancestors of *P*.  
  
Loggers have their additivity flag set to *true* by default. 

The table below shows an
example:

| Logger Name     | Added Appenders | Additivity Flag | Output Targets         | Comment                                                                                                                                           |
| --------------- | --------------- | --------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| root            | A1              | not applicable  | A1                     | The root logger is anonymous but can be accessed with the log4cxx::Logger::getRootLogger() method. There is no default appender attached to root. |
| x               | A-x1, A-x2      | true            | A1, A-x1, A-x2         | Appenders of "x" and root.                                                                                                                        |
| x.y             | none            | true            | A1, A-x1, A-x2         | Appenders of "x" and root.                                                                                                                        |
| x.y.z           | A-xyz1          | true            | A1, A-x1, A-x2, A-xyz1 | Appenders in "x.y.z", "x" and root.                                                                                                               |
| security        | A-sec           | false           | A-sec                  | No appender accumulation since the additivity flag is set to *false*.                                                                             |
| security.access | none            | true            | A-sec                  | Only appenders of "security" because the additivity flag in "security" is set to *false*.                                                         |

More often than not, users wish to customize not only the output
destination but also the output format. This is accomplished by
associating a *layout* with an appender. The layout is responsible for
formatting the logging request according to the user's wishes, whereas
an appender takes care of sending the formatted output to its
destination. 

The [PatternLayout](@ref log4cxx.PatternLayout),
part of the standard log4cxx distribution, lets the user specify the
output format according to conversion patterns similar to the C language
*printf* function. 

For example, the PatternLayout with the conversion pattern `%%r [%%t]
%%-5p %%c - %%m%%n` will output something akin to: 

~~~
176 [main] INFO org.foo.Bar - Located nearest gas station.
~~~

The first field is the number of milliseconds elapsed since the start of
the program. The second field is the thread making the log request. The
third field is the level of the log statement. The fourth field is the
name of the logger associated with the log request. The text after the
'-' is the message of the statement. 

# Configuration {#configuration}

Inserting log requests into the application code requires a fair amount
of planning and effort. Observation shows that approximately 4 percent
of code is dedicated to logging. Consequently, even moderately sized
applications will have thousands of logging statements embedded within
their code. Given their number, it becomes imperative to manage these
log statements without the need to modify them manually. 

The log4cxx environment is fully configurable programmatically. However,
it is far more flexible to configure log4cxx using configuration files.
Currently, configuration files can be written in XML or in Java
properties (key=value) format. 

Let us give a taste of how this is done with the help of an imaginary
application *MyApp* that uses log4cxx. 

~~~{.cpp}
    #include "com/foo/bar.h"
    using namespace com::foo;
     
    // include log4cxx header files.
    #include "log4cxx/logger.h"
    #include "log4cxx/basicconfigurator.h"
    #include "log4cxx/helpers/exception.h"
     
    using namespace log4cxx;
    using namespace log4cxx::helpers;
     
    LoggerPtr logger(Logger::getLogger("MyApp"));
     
    int main(int argc, char **argv)
    {
    	int result = EXIT_SUCCESS;
    	try
    	{
    		// Set up a simple configuration that logs on the console.
    		BasicConfigurator::configure();
     
    		LOG4CXX_INFO(logger, "Entering application.");
    		Bar bar;
    		bar.doIt();
    		LOG4CXX_INFO(logger, "Exiting application.");
    	}
    	catch(Exception&)
    	{
    		result = EXIT_FAILURE;
    	}
     
    	return result;
    }
~~~

*MyApp* begins by including log4cxx headers. It then defines a static
logger variable with the name *MyApp* which happens to be the fully
qualified name of the class. 

*MyApp* uses the *Bar* class defined in header file *com/foo/bar.h*. 

~~~{.cpp}
    // file com/foo/bar.h
    #include "log4cxx/logger.h"
     
    namespace com {
    	namespace foo {
    		class Bar {
    			static log4cxx::LoggerPtr logger;
     
    			public:
    				void doIt();
    		};
    	}
    }
~~~

~~~{.cpp}
    // file bar.cpp
    #include "com/foo/bar.h"
     
    using namespace com::foo;
    using namespace log4cxx;
     
    LoggerPtr Bar::logger(Logger::getLogger("com.foo.bar"));
     
    void Bar::doIt() {
    	LOG4CXX_DEBUG(logger, "Did it again!");
    }
~~~

The invocation of the
[BasicConfigurator::configure](@ref log4cxx.BasicConfigurator.configure)
method creates a rather simple log4cxx setup. This method is hardwired
to add to the root logger a [ConsoleAppender](@ref log4cxx.ConsoleAppender).
The output will be formatted using a
[PatternLayout](@ref log4cxx.PatternLayout)
set to the pattern `%%-4r [%%t] %%-5p %%c %%x - %%m%%n`. 

Note that by default, the root logger is assigned to
*Level::getDebug()*. 

The output of MyApp is: 

~~~
    0    [12345] INFO  MyApp  - Entering application.
    36   [12345] DEBUG com.foo.Bar  - Did it again!
    51   [12345] INFO  MyApp  - Exiting application.
~~~

The previous example always outputs the same log information.
Fortunately, it is easy to modify *MyApp* so that the log output can be
controlled at run-time. Here is a slightly modified version. 

~~~{.cpp}
    // file MyApp2.cpp
     
    #include "com/foo/bar.h"
    using namespace com::foo;
     
    // include log4cxx header files.
    #include "log4cxx/logger.h"
    #include "log4cxx/basicconfigurator.h"
    #include "log4cxx/propertyconfigurator.h"
    #include "log4cxx/helpers/exception.h"
     
    using namespace log4cxx;
    using namespace log4cxx::helpers;
    // Define a static logger variable so that it references the
    // Logger instance named "MyApp".
    LoggerPtr logger(Logger::getLogger("MyApp"));
     
    int main(int argc, char **argv)
    {
    	int result = EXIT_SUCCESS;
    	try
    	{
    		if (argc > 1)
    		{
    			// BasicConfigurator replaced with PropertyConfigurator.
    			PropertyConfigurator::configure(argv[1]);
    		}
    		else
    		{
    			BasicConfigurator::configure();
    		}
     
    		LOG4CXX_INFO(logger, "Entering application.");
    		Bar bar;
    		bar.doIt();
    		LOG4CXX_INFO(logger, "Exiting application.");
    	}
    	catch(Exception&)
    	{
    		result = EXIT_FAILURE;
    	}
     
    	return result;
    }
~~~

This version of *MyApp* instructs *PropertyConfigurator* to parse a
configuration file and set up logging accordingly. 

Here is a sample configuration file that results in exactly same output
as the previous *BasicConfigurator* based example. 

~~~
    # Set root logger level to DEBUG and its only appender to A1.
    log4j.rootLogger=DEBUG, A1
     
    # A1 is set to be a ConsoleAppender.
    log4j.appender.A1=org.apache.log4j.ConsoleAppender
     
    # A1 uses PatternLayout.
    log4j.appender.A1.layout=org.apache.log4j.PatternLayout
    log4j.appender.A1.layout.ConversionPattern=%-4r [%t] %-5p %c %x - %m%n
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
    2000-09-07 14:07:41,508 [12345] INFO  MyApp - Entering application.
    2000-09-07 14:07:41,529 [12345] INFO  MyApp - Exiting application.
~~~

As the logger *com.foo.Bar* does not have an assigned level, it inherits
its level from *com.foo*, which was set to WARN in the configuration
file. The log statement from the *Bar::doIt* method has the level DEBUG,
lower than the logger level WARN. Consequently, *doIt()* method's log
request is suppressed. 

Here is another configuration file that uses multiple appenders. 

~~~
    log4j.rootLogger=debug, stdout, R
     
    log4j.appender.stdout=org.apache.log4j.ConsoleAppender
    log4j.appender.stdout.layout=org.apache.log4j.PatternLayout
     
    # Pattern to output the caller's file name and line number.
    log4j.appender.stdout.layout.ConversionPattern=%5p [%t] (%F:%L) - %m%n
     
    log4j.appender.R=org.apache.log4j.RollingFileAppender
    log4j.appender.R.File=example.log
     
    log4j.appender.R.MaxFileSize=100KB
    # Keep one backup file
    log4j.appender.R.MaxBackupIndex=1
     
    log4j.appender.R.layout=org.apache.log4j.PatternLayout
    log4j.appender.R.layout.ConversionPattern=%p %t %c - %m%n
~~~

Calling the enhanced MyApp with the this configuration file will output
the following on the console. 

~~~
    INFO [12345] (MyApp2.cpp:31) - Entering application.
    DEBUG [12345] (Bar.h:16) - Doing it again!
    INFO [12345] (MyApp2.cpp:34) - Exiting application.
~~~

In addition, as the root logger has been allocated a second appender,
output will also be directed to the *example.log* file. This file will
be rolled over when it reaches 100KB. When roll-over occurs, the old
version of *example.log* is automatically moved to *example.log.1*. 

Note that to obtain these different logging behaviors we did not need to
recompile code. We could just as easily have logged to a UNIX Syslog
daemon, redirected all *com.foo* output to an NT Event logger, or
forwarded logging events to a remote log4cxx server, which would log
according to local server policy, for example by forwarding the log
event to a second log4cxx server. 

# Default Initialization Procedure {#default-initialization-procedure}

The log4cxx library does not make any assumptions about its environment.
In particular, there are no default log4cxx appenders. Under certain
well-defined circumstances however, the static inializer of the *Logger*
class will attempt to automatically configure log4cxx. 

The exact default initialization algorithm is defined as follows: 

1.  Set the configurationOptionStr string variable to the value of the
    **LOG4CXX\_CONFIGURATION** environment variable if set, otherwise
    the value of the **log4j.configuration** environment variable if
    set, otherwise the first of the following file names which exist in
    the current working directory, "log4cxx.xml", "log4cxx.properties",
    "log4j.xml" and "log4j.properties". If configurationOptionStr has
    not been set, then disable logging. 
2.  Unless a custom configurator is specified using the
    **LOG4CXX\_CONFIGURATOR\_CLASS** or **log4j.configuratorClass**
    environment variable, the PropertyConfigurator will be used to
    configure log4cxx unless the file name ends with the ".xml"
    extension, in which case the DOMConfigurator will be used. If a
    custom configurator is specified, the environment variable should
    contain a fully qualified class name of a class that implements the
    Configurator interface. 

# Nested Diagnostic Contexts {#nested-diagnostic-contexts}

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
into the NDC, the abbreviation of *Nested Diagnostic Context*. The NDC
class is shown below. 

~~~{.cpp}
    namespace log4cxx {
    	class NDC {
    		public:
    			// pushes the value on construction and pops on destruction.
    			NDC(const std::string& value);
    			NDC(const std::wstring& value);
     
    			// Remove the top of the context from the NDC.
    			static LogString pop();
     
    			// Add diagnostic context for the current thread.
    			static void push(const std::string& message);
    			static void push(const std::wstring& message);
    	}
    }
~~~

The NDC is managed per thread as a *stack* of contextual information.
Note that all methods of the *log4cxx::NDC* class are static. Assuming
that NDC printing is turned on, every time a log request is made, the
appropriate log4cxx component will include the *entire* NDC stack for
the current thread in the log output. This is done without the
intervention of the user, who is responsible only for placing the
correct information in the NDC by using the *push* and *pop* methods at
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
log4cxx releases support multiple hierarchy trees. This enhancement
allows each virtual host to possess its own copy of the logger
hierarchy. 

# Performance {#performance}

One of the often-cited arguments against logging is its computational
cost. This is a legitimate concern as even moderately sized applications
can generate thousands of log requests. Much effort was spent measuring
and tweaking logging performance. Log4cxx claims to be fast and
flexible: speed first, flexibility second. 

The user should be aware of the following performance issues. 

1.  **Logging performance when logging is turned off.** 
    
    When logging is turned off entirely or just for a set of levels, the
    cost of a log request consists of a method invocation plus an
    integer comparison. The LOG4CXX\_DEBUG and similar macros suppress
    unnecessary expression evaluation if the request is not enabled. 

2.  **The performance of deciding whether to log or not to log when
    logging is turned on.** 
    
    This is essentially the performance of walking the logger hierarchy.
    When logging is turned on, log4cxx still needs to compare the level
    of the log request with the level of the request logger. However,
    loggers may not have an assigned level; they can inherit them from
    the logger hierarchy. Thus, before inheriting a level, the logger
    may need to search its ancestors. 
    
    There has been a serious effort to make this hierarchy walk to be as
    fast as possible. For example, child loggers link only to their
    existing ancestors. In the *BasicConfigurator* example shown
    earlier, the logger named *com.foo.Bar* is linked directly to the
    root logger, thereby circumventing the nonexistent *com* or
    *com.foo* loggers. This significantly improves the speed of the
    walk, especially in "sparse" hierarchies. 
    
    The cost of walking the hierarchy is typically 3 times slower than
    when logging is turned off entirely. 

3.  **Actually outputting log messages** 
    
    This is the cost of formatting the log output and sending it to its
    target destination. Here again, a serious effort was made to make
    layouts (formatters) perform as quickly as possible. The same is
    true for appenders. 

# Removing log statements {#removing-log-statements}

Sometimes, you may want to remove all log statements from your program,
either for speed purposes or to remove sensitive information.  This can easily
be accomplished at build-time when using the standard `LOG4CXX_[level]` macros
(`LOG4CXX_TRACE`, `LOG4CXX_DEBUG`, `LOG4CXX_INFO`, `LOG4CXX_WARN`,
`LOG4CXX_ERROR`, `LOG4CXX_FATAL`).

Log statements can be removed either above a certain level, or they
can be disabled entirely.

For example, if we want to remove all log statements within our program
that use the `LOG4CXX_[level]` family of macros, add a preprocessor
definition `LOG4CXX_THRESHOLD` set to 50001
or greater.  This will ensure that any log statement that uses the
`LOG4CXX_[level]`-macro will be compiled out of the program.  To remove
all log statements at `DEBUG` or below, set `LOG4CXX_THRESHOLD` to a
value between 10001-20000.

The levels are set as follows:

|Logger Level|Integer Value|
|------------|-------------|
|TRACE       |5000         |
|DEBUG       |10000        |
|INFO        |20000        |
|WARN        |30000        |
|ERROR(1)    |40000        |
|FATAL       |50000        |

(1) The `LOG4CXX_ASSERT` macro is the same level as `LOG4CXX_ERROR`

Note that this has no effect on other macros, such as using the
`LOG4CXX_LOG`, `LOG4CXX_LOGLS`, or `LOG4CXX_L7DLOG` family of macros.

# Removing location information {#removing-location information}

Whenever you log a message with Log4cxx, metadata about the location of the
logging statement is captured as well through the preprocessor.  This includes
the file name, the method name, and the line number.  If you would not like to
include this information in your build but you still wish to keep the log
statements, define `LOG4CXX_DISABLE_LOCATION_INFO` in your build system.  This
will allow log messages to still be created, but the location information
will be invalid.

# Logging Custom Types {#custom-types}

Often, the data that needs to be logged is not just standard data types
(such as int, string, etc), but amalgamations of those types in a data
structure such as a class or struct.  In order to log these custom types,
simply override an `operator<<` function, the same as if you would
print the custom type to `std::cout`.  This can be accomplished by
doing the following:

~~~{.cpp}
struct MyStruct {
	int x;
};

std::ostream& operator<<( std::ostream& stream, const MyStruct& mystruct ){
	stream << "[MyStruct x:" << mystruct.x << "]";
	return stream;
}

void someMethod(){
	MyStruct mine;
	mine.x = 90;
	LOG4CXX_INFO( logger, "Some important information: " << mine );
}
~~~

This will output data similar to the following:

~~~
0 [0x7fd1eed63bc0] INFO root null - Some important information: [MyStruct x:90]
~~~

# Logging with {fmt} {#logging-with-fmt}

One issue with utilizing log4cxx and its ostream style of logging is that log
statements can be very awkward if you need to precisely format something:

~~~{.cpp}
LOG4CXX_INFO( rootLogger, "Numbers can be formatted with excessive operator<<: "
			  << std::setprecision(3) << 22.456
			  << " And as hex: "
			  << std::setbase( 16 ) << 123 );
~~~

This leads to very awkward code to read and write, especially as iostreams don't
support positional arguments at all.

In order to get around this, one popular library(that has been standardized as
part of C++20) is [{fmt}](https://fmt.dev/latest/index.html).  Supporting
positional arguments and printf-like formatting, it makes for much clearer
code like the following:

~~~{.cpp}
LOG4CXX_INFO_FMT( rootLogger, "Numbers can be formatted with a format string {:.1f} and as hex: {:x}", 22.456, 123 );
~~~

Note that log4cxx does not include a copy of {fmt}, so you must include the
correct headers and linker flags in order to use the `LOG4CXX_[level]_FMT`
family of macros.

As with the standard logger macros, these macros will also be compiled out
if the `LOG4CXX_THRESHOLD` macro is set to a level that will compile out
the non-FMT macros.

A full example can be seen in the src/examples/cpp/format-string.cpp file.

# Filtering Messages {#filtering}

When dealing with large amounts of logging information, it can be useful
to filter on messages that we are interested in.  This filtering only
takes places after determining that the level of the current logger would
log the message in the first place.  When defining filters, note that
they can only be defined on a per-appender basis, they do not globally
affect anything.

The filtering system is similar in concept to Linux iptables rules, in
that there is a chain of filters that can accept a log message, deny the
log message, or pass the message on to the next filter. Accepting a log
message means that the message will be logged immediately without
consulting other filters.  Denying has the opposite affect, immediately
dropping the log message and not consulting any other filters.

See the documentation for [Filter](@ref log4cxx.Filter) for some more
information, or view a [configuration sample](@ref configuration-samples).

# Conclusions {#conclusions}

Apache Log4cxx is a popular logging package written in C++. One of its
distinctive features is the notion of inheritance in loggers. Using a
logger hierarchy it is possible to control which log statements are
output at arbitrary granularity. This helps reduce the volume of logged
output and minimize the cost of logging. 

One of the advantages of the log4cxx API is its manageability. Once the
log statements have been inserted into the code, they can be controlled
with configuration files. They can be selectively enabled or disabled,
and sent to different and multiple output targets in user-chosen
formats. The log4cxx package is designed so that log statements can
remain in shipped code without incurring a heavy performance cost.
