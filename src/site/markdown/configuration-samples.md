Configuration Samples {#configuration-samples}
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

The following snippets show various ways of configuring Log4cxx.

# Default Initialization Behaviour {#default-initialization}

The Log4cxx library does not make any assumptions about its environment.
In particular, when initially created the root [Logger](@ref log4cxx.Logger) has no appender.
However the library will attempt automatic configuration.

If the LoggerRepositoy is not yet configured on the first call to
[getLogger](@ref log4cxx.LogManager.getLogger) of [LogManager](@ref log4cxx.LogManager),
the [configure](@ref log4cxx.DefaultConfigurator.configure) method
of [DefaultConfigurator](@ref log4cxx.DefaultConfigurator) is called
via [ensureIsConfigured](@ref log4cxx.spi.LoggerRepository.ensureIsConfigured) method
of [LoggerRepository](@ref log4cxx.spi.LoggerRepository).

To use automatic configuration with a non-standard file name
create and use your own wrapper for [getLogger](@ref log4cxx.LogManager.getLogger).
A full example can be seen in the \ref com/foo/config3.cpp file.

# XML Files {#xmlfiles}

One way of configuring Log4cxx is with XML files.  The following are some examples
on various ways of using an XML file to configure the logging.

## XML Example 1 {#xml-example-1}

This simple example simply writes messages to stdout.
If you want to send messages to stderr instead, simply change the 'Target' value
to `System.err`.

~~~{.xml}
<?xml version="1.0" encoding="UTF-8" ?>
<log4j:configuration xmlns:log4j="http://jakarta.apache.org/log4j/">

  <appender name="ConsoleAppender" class="org.apache.log4j.ConsoleAppender">
    <param name="Target" value="System.out"/>
    <layout class="org.apache.log4j.PatternLayout">
      <param name="ConversionPattern" value="%m%n"/>
    </layout>
  </appender>

  <root>
     <priority value="info" />
     <appender-ref ref="ConsoleAppender"/>
  </root>

</log4j:configuration>
~~~

Sample output:
~~~
Hello there!
~~~

## XML Example 2 {#xml-example-2}

This example sends data to both stdout, as well as to a file.
With this configuration the "example.log" file will be created in our working directory.

~~~{.xml}
<?xml version="1.0" encoding="UTF-8" ?>
<log4j:configuration xmlns:log4j="http://jakarta.apache.org/log4j/">

  <appender name="ConsoleAppender" class="org.apache.log4j.ConsoleAppender">
    <param name="Target" value="System.out"/>
    <layout class="org.apache.log4j.PatternLayout">
      <param name="ConversionPattern" value="[%d{yyyy-MM-dd HH:mm:ss}] %c %-5p - %m%n"/>
    </layout>
  </appender>

  <appender name="FileAppender" class="org.apache.log4j.FileAppender">
    <param name="file" value="example.log" />
    <layout class="org.apache.log4j.PatternLayout">
      <param name="ConversionPattern" value="[%d{yyyy-MM-dd HH:mm:ss}] %c %-5p - %m%n" />
    </layout>
  </appender>

  <root>
     <priority value="info" />
     <appender-ref ref="ConsoleAppender"/>
     <appender-ref ref="FileAppender"/>
  </root>

</log4j:configuration>
~~~

Sample output:
~~~
[2020-12-24 15:57:35] root INFO  - Hello there!
~~~

## XML Example 3 {#xml-example-3}

This example shows how you can configure logging for a particular category.

Assume that our loggers are in our code as such:

~~~{.cpp}
	log4cxx::LoggerPtr root = log4cxx::Logger::getRootLogger();
	log4cxx::LoggerPtr com  = log4cxx::Logger::getLogger( "com" );
	log4cxx::LoggerPtr com_example = log4cxx::Logger::getLogger( "com.example" );

	LOG4CXX_INFO( root, "Hello there!" );
	LOG4CXX_DEBUG( com, "com logger debug" );
	LOG4CXX_DEBUG( com_example, "com.example debug message" );
	LOG4CXX_TRACE( com, "com debug message" );
	LOG4CXX_TRACE( com_example, "com.example trace message" );
~~~

For this configuration, we have set any logger that is at the `com` level or below
to be debug.  However, we have also set the logger `com.example` to have a more
verbose `trace` level to see more information from that particular logger.
The "example.log" file will be created in our temporary directory.

~~~{.xml}
<?xml version="1.0" encoding="UTF-8" ?>
<log4j:configuration xmlns:log4j="http://jakarta.apache.org/log4j/">

  <appender name="ConsoleAppender" class="org.apache.log4j.ConsoleAppender">
    <param name="Target" value="System.out"/>
    <layout class="org.apache.log4j.PatternLayout">
      <param name="ConversionPattern" value="[%d{yyyy-MM-dd HH:mm:ss}] %c %-5p - %m%n"/>
    </layout>
  </appender>

  <appender name="FileAppender" class="org.apache.log4j.FileAppender">
    <param name="file" value="${TMP}/example.log" />
    <layout class="org.apache.log4j.PatternLayout">
      <param name="ConversionPattern" value="[%d{yyyy-MM-dd HH:mm:ss}] %c %-5p - %m%n" />
    </layout>
  </appender>

  <root>
     <priority value="info" />
     <appender-ref ref="ConsoleAppender"/>
     <appender-ref ref="FileAppender"/>
  </root>

  <logger name="com" >
     <priority value="debug"/>
  </logger>

  <logger name="com.example" >
     <priority value="trace"/>
  </logger>

</log4j:configuration>
~~~

Sample output:

~~~
[2020-12-24 16:05:48] root INFO  - Hello there!
[2020-12-24 16:05:48] com DEBUG - com logger debug
[2020-12-24 16:05:48] com.example DEBUG - com.example debug message
[2020-12-24 16:05:48] com.example TRACE - com.example trace message
~~~

## XML Example 4 {#xml-example-4}

This example shows how to add a filter to an appender that will accept messages
that match a certain string.  If our loggers are configured as such:

~~~{.cpp}
	log4cxx::LoggerPtr root = log4cxx::Logger::getRootLogger();
	log4cxx::LoggerPtr com  = log4cxx::Logger::getLogger( "com" );
	log4cxx::LoggerPtr com_example = log4cxx::Logger::getLogger( "com.example" );
	LOG4CXX_INFO( root, "Hello there!" );
	LOG4CXX_DEBUG( com, "Starting to do the thing" );
	LOG4CXX_DEBUG( com_example, "A more specific logger" );
	LOG4CXX_TRACE( com, "Done with the thing" );
	LOG4CXX_TRACE( com_example, "A very specific message" );
~~~

and we only want to see messages that have the string "specific" in them, we can
create a filter chain that will accept messages that have that, and deny
everything else:

~~~{.xml}
<?xml version="1.0" encoding="UTF-8" ?>
<log4j:configuration xmlns:log4j="http://jakarta.apache.org/log4j/">
  <appender name="ConsoleAppender" class="org.apache.log4j.ConsoleAppender">
    <param name="Target" value="System.out"/>
    <layout class="org.apache.log4j.PatternLayout">
      <param name="ConversionPattern" value="[%d{yyyy-MM-dd HH:mm:ss}] %c %-5p - %m%n"/>
    </layout>

    <filter class="org.apache.log4j.varia.StringMatchFilter">
      <param name="StringToMatch"
             value="specific" />
      <param name="AcceptOnMatch" value="true" />
    </filter>

    <filter class="org.apache.log4j.varia.DenyAllFilter"/>
  </appender>

  <root>
     <priority value="trace" />
     <appender-ref ref="ConsoleAppender"/>
  </root>
</log4j:configuration>
~~~

Sample output:

~~~
[2021-03-26 20:20:36] com.example DEBUG - A more specific logger
[2021-03-26 20:20:36] com.example TRACE - A very specific message
~~~

Note that even though we have the root logger set to the most verbose level(trace),
the only messages that we saw were the ones with "specific" in them.

\example auto-configured.cpp
This is an example of logging in static initialization code and
using the current module name to select the Log4cxx configuration file.
