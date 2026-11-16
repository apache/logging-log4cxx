/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _LOG4CXX_ECS_LAYOUT_H
#define _LOG4CXX_ECS_LAYOUT_H

#include <log4cxx/layout.h>


namespace LOG4CXX_NS
{
/**
This layout outputs each event as a single line JSON object
using the field names of the
<a href="https://www.elastic.co/docs/reference/ecs">Elastic Common Schema (ECS)</a>,
as described in the <a href="https://github.com/elastic/ecs-logging/tree/main/spec">ECS logging specification</a>.
The output can be sent to Elasticsearch (for example, using Filebeat, Logstash or fluent-bit)
without further parsing.

The fields in each line are:

Field | Content | Included |
----- | ------- | -------- |
\@timestamp | The event time in UTC with millisecond precision, e.g. <code>2026-11-15T10:20:30.123Z</code> | always |
log.level | The event level, e.g. <code>INFO</code> | always |
message | The rendered message | always |
ecs.version | <code>1.2.0</code> | always |
log.logger | The logger name | always |
process.thread.name | The name of the thread that made the logging request (or its identifier when the name is not available) | always |
service.name | The <b>ServiceName</b> option value | when not empty |
service.version | The <b>ServiceVersion</b> option value | when not empty |
service.environment | The <b>ServiceEnvironment</b> option value | when not empty |
service.node.name | The <b>ServiceNodeName</b> option value | when not empty |
event.dataset | The <b>EventDataset</b> option value, or the <b>ServiceName</b> option value | when not empty |
tags | An array containing the nested diagnostic context (NDC) | when the NDC is not empty |
<i>key</i> | The value of each mapped diagnostic context (MDC) entry | when the MDC is not empty |
log.origin.file.name | The source file name of the logging request | when the <b>LocationInfo</b> option is true and location information is available |
log.origin.file.line | The source line number (a JSON number) | as above |
log.origin.function | The qualified function name, e.g. <code>com::foo::Bar::doIt</code> | as above |

Each mapped diagnostic context (MDC) entry is added using its key as the field name,
so an MDC key such as <code>trace.id</code> or <code>user.id</code> populates the ECS field of that name.
An MDC entry that has the same name as a field already added by this layout is not output,
so the JSON object never contains a duplicate field name.

Here is an example configuration that writes ECS JSON lines to a file:
~~~{.xml}
<log4j:configuration xmlns:log4j="http://jakarta.apache.org/log4j/">
<appender name="ECS" class="FileAppender">
  <param name="File" value="logs/MyApp.ecs.json" />
  <layout class="ECSLayout">
    <param name="ServiceName" value="MyApp" />
    <param name="ServiceVersion" value="1.2.3" />
    <param name="ServiceEnvironment" value="production" />
  </layout>
</appender>
<root>
  <priority value ="INFO" />
  <appender-ref ref="ECS" />
</root>
</log4j:configuration>
~~~

A logging request in this configuration produces a line like:
~~~{.json}
{"@timestamp":"2026-11-15T10:20:30.123Z","log.level":"INFO","message":"Hello","ecs.version":"1.2.0","log.logger":"com.foo.Bar","process.thread.name":"main","service.name":"MyApp","service.version":"1.2.3","service.environment":"production","event.dataset":"MyApp"}
~~~

To send the events to a log server instead,
use this layout in a [JSONSocketAppender](@ref log4cxx::net::JSONSocketAppender).
*/
class LOG4CXX_EXPORT ECSLayout : public Layout
{
	private:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(ECSLayoutPrivate, m_priv)

	public:
		DECLARE_LOG4CXX_OBJECT(ECSLayout)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(ECSLayout)
		LOG4CXX_CAST_ENTRY_CHAIN(Layout)
		END_LOG4CXX_CAST_MAP()

		ECSLayout();

		~ECSLayout();

		/**
		Use \c newValue as the <b>service.name</b> field value.
		An empty value (the default) omits the field.
		*/
		void setServiceName(const LogString& newValue);

		/**
		The <b>service.name</b> field value.
		*/
		const LogString& getServiceName() const;

		/**
		Use \c newValue as the <b>service.version</b> field value.
		An empty value (the default) omits the field.
		*/
		void setServiceVersion(const LogString& newValue);

		/**
		The <b>service.version</b> field value.
		*/
		const LogString& getServiceVersion() const;

		/**
		Use \c newValue as the <b>service.environment</b> field value,
		e.g. <code>production</code> or <code>staging</code>.
		An empty value (the default) omits the field.
		*/
		void setServiceEnvironment(const LogString& newValue);

		/**
		The <b>service.environment</b> field value.
		*/
		const LogString& getServiceEnvironment() const;

		/**
		Use \c newValue as the <b>service.node.name</b> field value,
		which identifies a particular instance of a service.
		An empty value (the default) omits the field.
		*/
		void setServiceNodeName(const LogString& newValue);

		/**
		The <b>service.node.name</b> field value.
		*/
		const LogString& getServiceNodeName() const;

		/**
		Use \c newValue as the <b>event.dataset</b> field value.
		When empty (the default), the <b>ServiceName</b> option value is used.
		*/
		void setEventDataset(const LogString& newValue);

		/**
		The <b>event.dataset</b> field value
		(the <b>ServiceName</b> option value when <b>EventDataset</b> is empty).
		*/
		const LogString& getEventDataset() const;

		/**
		Include the source code location (the <b>log.origin.*</b> fields)
		of the logging request when \c newValue is true.
		By default, location information is not included.
		*/
		void setLocationInfo(bool newValue);

		/**
		Is the source code location of the logging request included?
		*/
		bool getLocationInfo() const;

		/**
		Returns the content type output by this layout, i.e "application/json".
		*/
		LogString getContentType() const override;

		using Layout::activateOptions;
		/**
		\copybrief spi::OptionHandler::activateOptions()

		Calculates the length of the formatted output.
		*/
		void activateOptions() override;

		/**
		\copybrief spi::OptionHandler::setOption()

		Supported options | Supported values | Default value |
		-------------- | ---------------- | --------------- |
		ServiceName | {any} | - |
		ServiceVersion | {any} | - |
		ServiceEnvironment | {any} | - |
		ServiceNodeName | {any} | - |
		EventDataset | {any} | (the ServiceName value) |
		LocationInfo | True,False | false |

		\sa setServiceName, setServiceVersion, setServiceEnvironment,
		setServiceNodeName, setEventDataset, setLocationInfo
		*/
		void setOption(const LogString& option, const LogString& value) override;

		using Layout::format;
		/**
		Append the attributes of \c event as a single line JSON object onto \c output.
		*/
		void format(LogString& output, const spi::LoggingEventPtr& event) const override;

		/**
		The ECS layout handles the throwable contained in logging
		events. Hence, this method returns <code>false</code>.
		*/
		bool ignoresThrowable() const override
		{
			return false;
		}

}; // class ECSLayout

LOG4CXX_PTR_DEF(ECSLayout);
}  // namespace log4cxx

#endif // _LOG4CXX_ECS_LAYOUT_H
