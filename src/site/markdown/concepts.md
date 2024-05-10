Loggers, Appenders and Layouts {#concepts}
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

Log4cxx has three main components: *loggers*, *appenders* and *layouts*.
These three types of components work together to enable developers to
log messages according to message type and level, and to control at
runtime how these messages are formatted and where they are reported.

Configuration of the Log4cxx environment is typically done at
application initialization. The preferred way is by reading a
configuration file. This approach was discussed in [Runtime Configuration].

# Loggers {#loggers}

The first and foremost advantage of any logging API over plain
`std::cout` resides in its ability to disable certain log statements
while allowing others to print unhindered. This capability is provided
by assigning each logging request to a category.
A Log4cxx category is a name and it is held by a log4cxx::Logger instance.
The name of the class in which the logging request appears
is a commonly used naming scheme
but any category naming scheme may be used.
Logging category names (or equivalently logger name)
are case-sensitive.

## Naming {#naming}

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

Logger names follow a hierarchical naming rule.
A logger is said to be an *ancestor* of another logger if its name
followed by a dot is a prefix of the *descendant* logger name. A logger
is said to be a *parent* of a *child* logger if there are no ancestors
between itself and the descendant logger.

For example, the logger named `com.foo` is a parent of the logger
named `com.foo.Bar`. Similarly, `java` is a parent of `java.util`
and an ancestor of `java.util.Vector`. This naming scheme should be
familiar to most developers.

Sometimes a per object logger is useful.
When each class instance has a identifiable name
(e.g. when it is instantiated from configuration data)
add a member variable to hold a log4cxx::LoggerInstancePtr
and initialize it with a name that makes it a *descendant* of the class.
This allows activation of DEBUG logging for a single object
or all objects of that class.

## Instantiation {#getLogger}

The root logger resides at the top of the hierarchy. It is
exceptional in two ways:

1.  it always exists,
2.  it cannot be retrieved by name.

Use the class static method
log4cxx::Logger::getRootLogger or
log4cxx::LogManager::getRootLogger to retrieve it.

All other loggers are held in a log4cxx::spi::LoggerRepository singleton.
They can be retrieved by calling a log4cxx::Logger::getLogger
static class method which takes the name of the desired logger as an argument.
An instance of log4cxx::Logger is instantiated
if a logger of that name is not already held
by the log4cxx::spi::LoggerRepository instance.

The core Log4cxx API is made available by <code>\#include <log4cxx/logger.h></code>.
The commonly used log4cxx/logger.h methods and macros are listed below.

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
    // and any object that provides a
    // <code>operator<<(std::ostream&, ...)</code> overload.
    //
    #define LOG4CXX_TRACE(logger, expression) ...
    #define LOG4CXX_DEBUG(logger, expression) ...
    #define LOG4CXX_INFO(logger, expression) ...
    #define LOG4CXX_WARN(logger, expression) ...
    #define LOG4CXX_ERROR(logger, expression) ...
    #define LOG4CXX_FATAL(logger, expression) ...
~~~

Calling the *getLogger* method with the same name will always return a
reference to the exact same logger object.

For example, in

~~~{.cpp}
    auto x = log4cxx::Logger::getLogger("wombat");
    auto y = log4cxx::Logger::getLogger("wombat");
~~~

*x* and *y* refer to *exactly* the same logger object.

Thus, it is possible to configure a logger and then to retrieve the same
instance somewhere else in the code without passing around references.
In fundamental contradiction to biological parenthood, where parents
always preceed their children, Log4cxx loggers can be created and
configured in any order. In particular, a "parent" logger will find and
link to its descendants even if it is instantiated after them.

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

### Logging Custom Types {#custom-types}

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

### Using {fmt} style requests {#logging-with-fmt}

One issue with utilizing Log4cxx and its ostream style of logging is that log
statements can be very awkward if you need to precisely format something:

~~~{.cpp}
LOG4CXX_INFO( rootLogger, "Numbers can be formatted with excessive operator<<: "
			  << std::setprecision(3) << 22.456
			  << " And as hex: "
			  << std::setbase( 16 ) << 123 );
~~~

This leads to very awkward code to read and write, especially as iostreams don't
support positional arguments at all.

In order to get around this, Log4cxx provides a family of macros that
support positional arguments and printf-like formatting, which makes for much clearer
(and more efficient) code like the following:

~~~{.cpp}
LOG4CXX_INFO_FMT( rootLogger, "Numbers can be formatted with a format string {:.1f} and as hex: {:x}", 22.456, 123 );
~~~

The `LOG4CXX_[level]_FMT` macros use the [{fmt}](https://fmt.dev/latest/index.html) library by default.
Note that Log4cxx does not include a copy of {fmt}, so you must include the
correct headers and linker flags in order to use the `LOG4CXX_[level]_FMT`
family of macros.
Provide `LOG4CXX_FORMAT_NS=std` to the preprocessor to have
the `LOG4CXX_[level]_FMT` macros use the standard library version of [format](https://en.cppreference.com/w/cpp/utility/format/format).

As with the standard logger macros, these macros will also be compiled out
if the `LOG4CXX_THRESHOLD` macro is set to a level that will compile out
the non-FMT macros.

A full example can be seen in the \ref format-string.cpp file.

### Overhead {#request-cost}

One of the often-cited arguments against logging is its computational
cost. This is a legitimate concern as even moderately sized applications
can generate thousands of log requests. Much effort was spent measuring
and tweaking logging performance. Log4cxx claims to be fast and
flexible: speed first, flexibility second.

For performance sensitive applications, you should be aware of the following.

1.  **Logging performance when logging is turned off.**

    The LOG4CXX\_DEBUG and similar macros have a
    cost of an in-lined null pointer check plus an integer comparison
    when the logger not currently enabled for that level.
    The other terms inside the macro are not evaluated.

    When the level is enabled for a logger but the logging hierarchy is turned off
    entirely or just for a set of levels, the cost of a log request consists
    of a method invocation plus an integer comparison.

2.  **Actually outputting log messages**

    This is the cost of formatting the log output and sending it to its
    target destination. Here again, a serious effort was made to make
    layouts (formatters) perform as quickly as possible. The same is
    true for appenders.

3.  **The cost of changing a logger's level.**

    The threshold value stored in any child logger is updated.
    This is done iterating over the map of all known logger objects
    and walking the hierarchy of each.

    There has been a serious effort to make this hierarchy walk to be as
    fast as possible. For example, child loggers link only to their
    existing ancestors. In the *BasicConfigurator* example shown
    earlier, the logger named *com.foo.Bar* is linked directly to the
    root logger, thereby circumventing the nonexistent *com* or
    *com.foo* loggers. This significantly improves the speed of the
    walk, especially in "sparse" hierarchies.

### Removing log requests {#removing-log-statements}

Sometimes, you may want to remove all log statements from your program,
either for speed purposes or to remove sensitive information.  This can easily
be accomplished at build-time when using the standard `LOG4CXX_[level]` macros
(`LOG4CXX_TRACE`, `LOG4CXX_DEBUG`, `LOG4CXX_INFO`, `LOG4CXX_WARN`,
`LOG4CXX_ERROR`, `LOG4CXX_FATAL`)
or their {fmt} library equivalents
(`LOG4CXX_TRACE_FMT`, `LOG4CXX_DEBUG_FMT`, `LOG4CXX_INFO_FMT`, `LOG4CXX_WARN_FMT`,
`LOG4CXX_ERROR_FMT`, `LOG4CXX_FATAL_FMT`).

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

### Removing location information {#removing-location-information}

Whenever you log a message with Log4cxx, metadata about the location of the
logging statement is captured as well through the preprocessor.  This includes
the file name, the method name, and the line number.  If you would not like to
include this information in your build but you still wish to keep the log
statements, define `LOG4CXX_DISABLE_LOCATION_INFO` in your build system.  This
will allow log messages to still be created, but the location information
will be invalid.

## Levels {#levels}

A log4cxx::Logger instance *may* be assigned a specific level
otherwise it will inherit it from the
closest ancestor with an assigned level.
The root logger always has an assigned level.

The pre-defined levels: TRACE, DEBUG,
INFO, WARN, ERROR and FATAL are available.
These are defined in the log4cxx/level.h file.
Additional levels may be registered by the application
but this is not recommended (See [Custom_levels]).

A logging request is said to be *enabled* if its level is higher than or
equal to the level of its logger. Otherwise, the request is said to be
*disabled*. A logger without an assigned level will inherit one from the
hierarchy. This rule is summarized below.

### Level Inheritance {#level-inheritance}

The *effective level* for a given logger *X.Y.Z*, is equal to the first
assigned in the logger hierarchy, starting at *X.Y.Z* and proceeding
upwards in the hierarchy towards the *root* logger.

To ensure that all loggers can eventually inherit a level, the root
logger always has an assigned level.

Below are four tables with various assigned level values and the
resulting effective levels according to the above rule.

| Logger name | Assigned level | Effective level |
| ----------- | -------------- | --------------- |
| root        | INFO           | INFO            |
| X           | none           | INFO            |
| X.Y         | none           | INFO            |
| X.Y.Z       | none           | INFO            |

Example 1

In example 1 above, only the root logger is assigned a level. This level
value, *INFO*, is inherited by the other loggers *X*, *X.Y* and
*X.Y.Z*.

| Logger name | Assigned level | Effective level |
| ----------- | -------------- | --------------- |
| root        | INFO           | INFO            |
| X           | WARN           | WARN            |
| X.Y         | DEBUG          | DEBUG           |
| X.Y.Z       | TRACE          | TRACE           |

Example 2

In example 2, all loggers have an assigned level value. There is no
use of level inheritence.

| Logger name | Assigned level | Effective level |
| ----------- | -------------- | --------------- |
| root        | INFO           | INFO            |
| X           | DEBUG          | DEBUG           |
| X.Y         | none           | DEBUG           |
| X.Y.Z       | WARN           | WARN            |

Example 3

In example 3, the loggers *root*, *X* and *X.Y.Z* are assigned the
levels *INFO*, *DEBUG* and *WARN* respectively. The logger *X.Y* inherits
its level from its parent *X*.

| Logger name | Assigned level | Effective level |
| ----------- | -------------- | --------------- |
| root        | INFO           | INFO            |
| X           | DEBUG          | DEBUG           |
| X.Y         | none           | DEBUG           |
| X.Y.Z       | none           | DEBUG           |

Example 4

In example 4, the loggers *root* and *X* and are assigned the levels
*INFO* and *DEBUG* respectively. The loggers *X.Y* and *X.Y.Z* inherit
their level from their nearest parent having an assigned
level, *X*.

### Basic Selection Rule {#selection-rule}

A log request of level *p* in a logger with (either assigned or
inherited, whichever is appropriate) level *q*, is enabled if *p \>= q*.

This rule is at the heart of Log4cxx. It assumes that levels are
ordered. For the standard levels, we have *TRACE \< DEBUG \< INFO \<
WARN \< ERROR \< FATAL*.

Here is an example of this rule.

~~~{.cpp}
    // get a logger instance named "com.foo"
    auto logger = log4cxx::Logger::getLogger("com.foo");

    // Now set its level. Normally you do not need to set the
    // level of a logger programmatically. This is usually done
    // in configuration files.
    logger->setLevel(log4cxx::Level::getInfo());

    auto barlogger = log4cxx::Logger::getLogger("com.foo.Bar");

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

# Appenders {#appenders}

The ability to selectively enable or disable logging requests based on
their logger is only part of the picture.

Log4cxx allows logging requests to print to multiple destinations.
In Log4cxx speak, an output destination is called an *appender*.
Log4cxx provides appenders to write to:
- [stdout or stderr](@ref log4cxx.ConsoleAppender)
- [files](@ref log4cxx.rolling.RollingFileAppender)
- [the NT Event log](@ref log4cxx.nt.NTEventLogAppender)
- [the UNIX Syslog](@ref log4cxx.net.SyslogAppender)
- [a TCP port](@ref log4cxx.net.TelnetAppender)
- [a remote log processor](@ref log4cxx.net.XMLSocketAppender)
- [a SMTP server](@ref log4cxx.net.SMTPAppender)
- [a database](@ref log4cxx.db.ODBCAppender)

If the same file receives log requests concurrently from multiple process,
use [this appender](@ref log4cxx.rolling.MultiprocessRollingFileAppender).
It is also possible to log [asynchronously](@ref log4cxx.AsyncAppender)
to another appender.
See \ref async-example.xml

The [addAppender](@ref log4cxx.Logger.addAppender)
method adds an appender to a given logger.
More than one appender can be attached to a logger.

## Additivity {#appender-additivity}

Each enabled logging request for a given logger will be forwarded to all the appenders in
that logger as well as the appenders higher in the hierarchy.
In other words, appenders are inherited additively from the logger hierarchy.
For example, if a console appender is added to the root logger, then all
enabled logging requests will at least print on the console. If in
addition a file appender is added to a logger, say *C*, then enabled
logging requests for *C* and *C*'s children will print on a file *and*
on the console. It is possible to override this default behavior so that
appender accumulation is no longer additive by
[setting the additivity flag](@ref log4cxx.Logger.setAdditivity) to `false`.

The rules governing appender additivity are summarized below.

The output of a log statement of logger *C* will go to all the appenders
in *C* and its ancestors. This is the meaning of the term "appender
additivity". However, if an ancestor of logger *C*, say *P*, has the
additivity flag set to *false*, then *C*'s output will be directed to
all the appenders in *C* and it's ancestors up to and including *P* but,
not the appenders in any of the ancestors of *P*.

Loggers have their additivity flag set to *true* by default,
meaning output goes to the appender attached to a
parent [Logger](@ref log4cxx.Logger).
It is therefore often sufficient to configure or attach an appender
only to the root logger in the [Hierarchy](@ref log4cxx.Hierarchy).

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

# Layouts {#layouts}

More often than not, users wish to customize not only the output
destination but also the output format. This is accomplished by
associating a *layout* with an appender. The layout is responsible for
formatting the logging request according to the user's wishes, whereas
an appender takes care of sending the formatted output to its
destination.

The [PatternLayout](@ref log4cxx.PatternLayout),
part of the standard Log4cxx distribution, lets the user specify the
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

The following examples show how you might configure the PatternLayout in order to
achieve the results shown.
Each example has two blocks of code: the layout for the PatternLayout,
and a sample output message.

## Pattern 1 {#pattern1}

This pattern contains the date in an ISO-8601 format(without fractional seconds),
followed by the logger name, the level, and then the message.

~~~
[%d{yyyy-MM-dd HH:mm:ss}] %c %-5p - %m%n
~~~

~~~
[2020-12-24 15:31:46] root INFO  - Hello there!
~~~

## Pattern 2 {#pattern2}

Similar to Pattern 1, except using ISO-8601 with fractional seconds

~~~
[%d] %c %-5p - %m%n
~~~

~~~
[2020-12-24 15:35:39,225] root INFO  - Hello there!
~~~

## Pattern 3 {#pattern3}

Prints out the number of milliseconds since the start of the application,
followed by the level(5 character width), followed by the logger name
(20 character width), followed by the message.

~~~
%r %-5p %-20c %m%n
~~~

~~~
0 INFO  root                 Hello there!
~~~

## Pattern 4 {#pattern4}

If you have no idea where a log message is coming from, it's possible to print
out more information about the place the log statement is coming from.  For example,
we can get the filename, class name, method name, and line number in one log
message.  This utilises the %%F(file name), %%C(class name), %%M(method name), %%L(line number)
patterns to output more information:

~~~
(%F:%C[%M]:%L) %m%n
~~~

Possible output:
~~~
(/home/robert/log4cxx-test-programs/fooclass.cpp:FooClass[FooClass]:9) Constructor running
(/home/robert/log4cxx-test-programs/fooclass.cpp:FooClass[doFoo]:13) Doing foo
~~~

Note that unlike Java logging, the location information is free(as it utilizes
macros to determine this information at compile-time).

The other layouts provided in Log4cxx are:

- [libfmt patterns](@ref log4cxx.FMTLayout)
- [a HTML table](@ref log4cxx.HTMLLayout)
- [a JSON dictionary](@ref log4cxx.JSONLayout)
- [level - message](@ref log4cxx.SimpleLayout)
- [log4j event elements](@ref log4cxx.xml.XMLLayout)

\example format-string.cpp
This example shows logging using the [{fmt}](https://fmt.dev/latest/index.html) library.

\example async-example.xml
This example shows a configuration using the [asynchronous appender](@ref log4cxx.AsyncAppender).

[Custom_levels]:faq.html#custom_levels
[Runtime Configuration]:quick-start.html#configuration
