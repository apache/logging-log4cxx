LocationInfoFilter {#location-info-filter}
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

The LocationInfoFilter allows filtering against the location in the file that
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
