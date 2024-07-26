Filtering Log Messages {#filters}
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


# Labeling Log Output {#labeling-log-output}

To uniquely stamp each request to relate it to a particular source,
you can push contextual information
into the *Nested Diagnostic Context* (NDC) using the *log4cxx::NDC* class
or the *Mapped Diagnostic Context* provided by *log4cxx::MDC* class.
For an example using log4cxx::NDC refer to \ref ndc-example.cpp.

The NDC is managed per thread as a *stack* of contextual information.
When the layout specifies that the NDC is to be included,
each log entry will include the entire stack for the current thread.
A log4cxx::PatternLayout allows named entries of the MDC
to be included in the log message.
The user is responsible for placing the correct information in the NDC/MDC
by creating a *log4cxx::NDC* or *log4cxx::MDC* stack variable at
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
Log4cxx releases support multiple hierarchy trees. This enhancement
allows each virtual host to possess its own copy of the logger
hierarchy.

# Excluding Log Output {#excluding-log-output}

When dealing with large amounts of logging information, it can be useful
to filter on messages that we are interested in.  This filtering only
takes places after determining that the level of the current logger would
log the message in the first place (as shown in detail by [the flow chart]).
Note that filters can only be applied on a per-appender basis,
they do not globally affect anything.

The filtering system is similar in concept to Linux iptables rules, in
that there is a chain of filters that can accept a log message, deny the
log message, or pass the message on to the next filter. Accepting a log
message means that the message will be logged immediately without
consulting other filters.  Denying has the opposite affect, immediately
dropping the log message and not consulting any other filters.

See the documentation for [Filter](@ref log4cxx.spi.Filter) for some more
information, or view a [configuration sample](@ref configuration-samples).

The following filters are available:
* [AndFilter](@ref log4cxx.filter.AndFilter) - Takes in a list of filters that must all match
* [DenyAllFilter](@ref log4cxx.filter.DenyAllFilter) - Drops all log messages that reach it
* [LevelMatchFilter](@ref log4cxx.filter.LevelMatchFilter) - Filter log messages based off of their level
* [LevelRangeFilter](@ref log4cxx.filter.LevelRangeFilter) - Filter log messages based off of their level in a given range
* [LocationInfoFilter](@ref log4cxx.filter.LocationInfoFilter) - Filter log messages based off of their location(line number and/or method name)
* [LoggerMatchFilter](@ref log4cxx.filter.LoggerMatchFilter) - Accept or deny depending on the logger that generated the message
* [MapFilter](@ref log4cxx.filter.MapFilter) - Based off of the log messages MDC, accept or deny the message
* [StringMatchFilter](@ref log4cxx.filter.StringMatchFilter) - If the given substring is found in the message, accept or deny

# Runtime Configuration {#configure-filter}

## Using MDC Values {#map-filter}

The [MapFilter](@ref log4cxx.filter.MapFilter) allows filtering against data elements that are in the *Mapped Diagnostic Context* (*log4cxx::MDC*).

| **Parameter Name** | **Type**  | **Description**                                                                                                                                                                                                    |
|:-------------------|:----------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Operator           | LogString | If the operator is `AND` then all the key/value pairs must match; any other value is implicitly an `OR` and a match by any one of the key/value pairs will be considered to be a match. The default value is `OR`. |
| AcceptOnMatch      | LogString | Action to take when the filter matches. May be `true` or `false`. The default value is `false`.                                                                                                                    |
| MDC key            | LogString | Any name other than `Operator` or `AcceptOnMatch` is considered a key to the MDC along with the value to match on. Keys may only be specified once; duplicate keys will replace earlier ones.                      |

In this configuration, the [MapFilter](@ref log4cxx.filter.MapFilter) can be used to filter based on system inserted values such as IP address and/or Username. In this example, we assume that the program has inserted appropriate values for `user.ip` and `user.name` into the MDC. In this case, when both the IP address is `127.0.0.1` and the Username is `test`, the entry will not be logged.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<log4j:configuration xmlns:log4j="http://logging.apache.org/">
	<appender name="SIMPLE" class="log4cxx.FileAppender">
		<layout class="log4cxx.SimpleLayout">
			<param	name="File"
					value="logs/app.log"
			/>
			<param	name="Append"
					value="true"
			/>
		</layout>

		<filter class="log4cxx.MapFilter">
			<param	name="user.ip"
					value="127.0.0.1"
			/>
			<param	name="user.name"
					value="test"
			/>
			<param	name="Operator"
					value="AND"
			/>
			<param	name="AcceptOnMatch"
					value="false"
			/>
		</filter>
	</appender>

	<root>
		<priority		value="all"		/>
		<appender-ref	ref="SIMPLE"	/>
	</root>
</log4j:configuration>
```

If we wanted to exclude multiple IP addresses from the log, we need to define a separate filter for each one as we don’t support wildcards. Since the default `AcceptOnMatch` value is `false`, we can simplify to a single line per filter. In the configuration below we would skip logs for IP addresses matching 192.168.0.5 - 7.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<log4j:configuration xmlns:log4j="http://logging.apache.org/">
	<appender name="SIMPLE" class="log4cxx.FileAppender">
		<layout class="log4cxx.SimpleLayout">
			<param	name="File"
					value="logs/app.log"
			/>
			<param	name="Append"
					value="true"
			/>
		</layout>

		<filter class="MapFilter">
			<param	name="user.ip" 
					value="192.168.0.5"
			/>
		</filter>
		<filter class="MapFilter">
			<param	name="user.ip"
					value="192.168.0.6"
			/>
		</filter>
		<filter class="MapFilter">
			<param	name="user.ip"
					value="192.168.0.7"
			/>
		</filter>
	</appender>

	<root>
		<priority		value="all"		/>
		<appender-ref	ref="SIMPLE"	/>
	</root>
</log4j:configuration>
```

In the case where we only want to log entries from a particular set of IP addresses (**not recommended** as this could be a security vulnerability), we need to have a final `DenyAllFilter` to catch the fall through. In this configuration, we would **only** log entries from 192.168.0.251 and 192.168.0.252.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<log4j:configuration xmlns:log4j="http://logging.apache.org/">
	<appender name="SIMPLE" class="log4cxx.FileAppender">
		<layout class="log4cxx.SimpleLayout">
			<param	name="File"
					value="logs/app.log"
			/>
			<param	name="Append"
					value="true"
			/>
		</layout>

		<filter class="MapFilter">
			<param	name="user.ip"
					value="192.168.0.251"
			/>
			<param	name="AcceptOnMatch"
					value="true"
			/>
		</filter>
		<filter class="MapFilter">
			<param	name="user.ip"
					value="192.168.0.252"
			/>
			<param	name="AcceptOnMatch"
					value="true"
			/>
		</filter>
		<filter class="DenyAllFilter" />
	</appender>

	<root>
		<priority		value="all"		/>
		<appender-ref	ref="SIMPLE"	/>
	</root>
</log4j:configuration>
```

## Using the Request Location {#location-info-filter}

The [LocationInfoFilter](@ref log4cxx.filter.LocationInfoFilter) allows filtering against the location in the file that
the log statement was made.  Location information must not be disabled in order
for this filter to be effective.  Location information is disabled with the
`LOG4CXX_DISABLE_LOCATION_INFO` macro.

| **Parameter Name** | **Type**  | **Description**                                                                                                                                                                                                    |
|:-------------------|:----------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Operator           | LogString | If the operator is `AND` then all the parts of the location(line number and method name) must match.  If set to `OR` then only one needs to match.  The default value is `OR`. |
| AcceptOnMatch      | bool | If `true`, accept the message when it matches the parameters.  If `false`, deny the message when it matches the parameters. |
| LineNumber         | int | The line number to match on.  The default line number is -1. |
| Method             | LogString | The method to match on.  The method name may be compiler-specific.  On GCC, the method name will look like `Class::methodName` |

Assume that our code looks something like the following:

~~~{.cpp}
	LOG4CXX_TRACE(logger, "About to do something!");
	for( int x = 0; x < 100; x++ ){
		LOG4CXX_TRACE(logger, "Do something number " << x);
	}
~~~

For various reasons, we may want to know that we are about to do something, but
we don't want to know each iteration of the loop.  In order to filter out this
one message we can create a LocationInfoFilter in order to specifiy the line
number that this message is on in order to filter it out:

~~~{.xml}
<?xml version="1.0" encoding="UTF-8"?>
<log4j:configuration xmlns:log4j="http://logging.apache.org/">
    <appender name="SIMPLE" class="ConsoleAppender">
        <param name="Target" value="System.err"/>
    
        <layout class="org.apache.log4j.PatternLayout">
            <param name="ConversionPattern" value="%p - %m%n"/>
        </layout>

        <filter class="LocationInfoFilter">
            <param  name="LineNumber" value="182" />
            <param  name="Operator" value="OR" />
            <param  name="AcceptOnMatch" value="false" />
        </filter>
    </appender>
    <root>
        <priority       value="all"     />
        <appender-ref   ref="SIMPLE"    />
    </root>
</log4j:configuration>
~~~

Doing this allows us to still see the "About to do something!" message, but
ignore each iteration of the loop.


\example ndc-example.cpp
This example shows how to add a context string to each logging message using the NDC.

[the flow chart]:log-flow.html
