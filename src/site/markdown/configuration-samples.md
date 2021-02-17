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

The following snippets show various ways of configuring log4cxx.

[TOC]

# Patterns {#patterns}

The basic way of outputing messages is by using a [PatternLayout](@ref log4cxx.PatternLayout),
and then sending the messages to stderr/stdout/file.  The following
examples show how you might configure the PatternLayout in order to
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

# XML Files {#xmlfiles}

One way of configuring log4cxx is with XML files.  The following are some examples
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

This example sends data to both stdout, as well as to a file.  In this case,
the file will be in our working directory.  The pattern has also been updated
to match with pattern example 1

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
