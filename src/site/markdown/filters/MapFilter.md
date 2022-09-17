MapFilter {#map-filter}
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

The MapFilter allows filtering against data elements that are in the Mapped Diagnostic Context (MDC).

| **Parameter Name** | **Type**  | **Description**                                                                                                                                                                                                    |
|:-------------------|:----------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Operator           | LogString | If the operator is `AND` then all the key/value pairs must match; any other value is implicitly an `OR` and a match by any one of the key/value pairs will be considered to be a match. The default value is `OR`. |
| AcceptOnMatch      | LogString | Action to take when the filter matches. May be `true` or `false`. The default value is `false`.                                                                                                                    |
| MDC key            | LogString | Any name other than `Operator` or `AcceptOnMatch` is considered a key to the MDC along with the value to match on. Keys may only be specified once; duplicate keys will replace earlier ones.                      |

In this configuration, the MapFilter can be used to filter based on system inserted values such as IP address and/or Username. In this example, we assume that the program has inserted appropriate values for `user.ip` and `user.name` into the MDC. In this case, when both the IP address is `127.0.0.1` and the Username is `test`, the entry will not be logged.

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
