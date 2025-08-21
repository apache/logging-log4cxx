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
A full example can be seen in the \ref com/foo/config4.cpp file.

# Runtime Property Values {#runtime-property-values}

The value of an enviroment variable can be used in a property value.
Instances of the form <b>${VarName}</b> will be replaced
with the value of the environment variable <b>VarName</b>.
A warning message is output to stderr if the closing brace is absent.

As of version 1.6, Log4cxx allows you to define configuration variables programmatically.
Extra key value pairs may be added prior to loading a configuration file using code such as:
~~~{.cpp}
auto& props = log4cxx::spi::Configurator::properties();
props.setProperty(LOG4CXX_STR("VarName"), LOG4CXX_STR("my-varname-value"));
~~~

Also available in Log4cxx 1.6 are variables that hold the currently executing program file path
and the [std::filesystem::path](https://en.cppreference.com/w/cpp/filesystem/path.html)
decomposition of the currently executing program file path.
These allow you to specify a log file location
relative to the executable location,
not just the current working directory.
The variable names are [documented here](@ref log4cxx.spi.Configurator.properties).

# Properties Files {#properties}

Log4cxx may be configured using a Java properties (key=value) type file.

The following Log4cxx 1.6 configuration file uses
the variables added in the \ref com/foo/config4.cpp example.
~~~
# Uncomment a line to enable debugging for a category
log4j.rootCategory=INFO, A1

log4j.appender.A1=org.apache.log4j.RollingFileAppender
log4j.appender.A1.MaxFileSize=5MB
log4j.appender.A1.MaxBackupIndex=12
log4j.appender.A1.File=${LocalAppData}/${CURRENT_VENDOR_FOLDER}/${CURRENT_PRODUCT_FOLDER}/Logs/${PROGRAM_FILE_PATH.STEM}.log
log4j.appender.A1.Append=true
log4j.appender.A1.layout=org.apache.log4j.PatternLayout
log4j.appender.A1.layout.ConversionPattern=%d{yyyy-MM-dd HH:mm:ss.SSS} [%t] %-5p %.30c - %m%n

log4j.appender.console=org.apache.log4j.ConsoleAppender
log4j.appender.console.layout=org.apache.log4j.PatternLayout
log4j.appender.console.layout.ConversionPattern=%.30c - %m%n

log4j.appender.csvData=org.apache.log4j.FileAppender
log4j.appender.csvData.File=${LocalAppData}/${CURRENT_VENDOR_FOLDER}/${CURRENT_PRODUCT_FOLDER}/MessageData.csv
log4j.appender.csvData.Append=false
log4j.appender.csvData.layout=org.apache.log4j.PatternLayout
log4j.appender.csvData.layout.ConversionPattern=%m,%d{yyyy-MM-dd,HH:mm,ss.SSS}%n

#log4j.logger.csv.URCommunicationPort=DEBUG, csvData
#log4j.logger.csv.URCommunicationPort.additivity=false

# UnitTests
#log4j.logger.MockArmTests=DEBUG
#log4j.logger.RTDEMessageTests=DEBUG
#log4j.logger.RTDEMessagePortTests=DEBUG
#log4j.logger.URCommunicationPortTests=DEBUG

# URControl classes
#log4j.logger.Dashboard=DEBUG
#log4j.logger.RTDEMessage=DEBUG
#log4j.logger.RTDEMessagePort=DEBUG
#log4j.logger.MockArm=DEBUG
#log4j.logger.MockURController=DEBUG
#log4j.logger.URCommunicationPort=DEBUG
~~~

# XML Files {#xmlfiles}

Another way of configuring Log4cxx is with an XML file.
The following are some XML configuration examples.

## XML Example 1 {#xml-example-1}

This simple example writes messages to stdout.
If you want to send messages to stderr instead,
change the 'Target' value to `System.err`.

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
The log file will be created in a program data directory
where the path uses the program vendor and product name.

The following Log4cxx 1.6 configuration file uses
the variables added in the \ref com/foo/config4.cpp example.

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
    <param name="file" value="${LocalAppData}/${CURRENT_VENDOR_FOLDER}/${CURRENT_PRODUCT_FOLDER}/Logs/${PROGRAM_FILE_PATH.STEM}.log" />
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
using the current module name (auto-configured) to select the Log4cxx configuration file.
In this example Log4cxx is configured by loading \ref auto-configured.xml.
The function <code>com::foo::getLogger()</code>, which is called during initialization,
is implemented in the \ref com/foo/config4.cpp file.



\example auto-configured.xml
