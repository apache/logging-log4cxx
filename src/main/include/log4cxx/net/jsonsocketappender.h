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

#ifndef _LOG4CXX_NET_JSON_SOCKET_APPENDER_H
#define _LOG4CXX_NET_JSON_SOCKET_APPENDER_H

#include <log4cxx/net/socketappenderskeleton.h>

namespace LOG4CXX_NS
{
namespace net
{

/**
Sends spi::LoggingEvent elements
to a remote a log server, usually in JSON format.

Here is an example configuration that writes JSON to the
<a href="https://docs.fluentbit.io/manual/pipeline/inputs/tcp">TCP input plugin of a fluent-bit log server</a>
running on the same system as the application:
~~~{.xml}
<log4j:configuration xmlns:log4j="http://jakarta.apache.org/log4j/">
<appender name="A1" class="JSONSocketAppender">
  <param name="RemoteHost" value="localhost" />
  <param name="Port"       value="5170" />
  <param name="Threshold"  value="INFO" />
</appender>
<root>
  <priority value ="INFO" />
  <appender-ref ref="A1" />
</root>
</log4j:configuration>
~~~

See \ref socket_appender_properties "SocketAppenderSkeleton" for more information on the behaviour this appender.
*/

class LOG4CXX_EXPORT JSONSocketAppender : public SocketAppenderSkeleton
{
	public:
		DECLARE_LOG4CXX_OBJECT(JSONSocketAppender)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(JSONSocketAppender)
		LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
		END_LOG4CXX_CAST_MAP()

		/**
		An unconnected appender using the default port.
		*/
		JSONSocketAppender();
		/**
		Close and shutdown the connection if not already done.
		*/
		~JSONSocketAppender();

		/**
		Connects to remote server at <code>address</code> and <code>port</code>.
		*/
		JSONSocketAppender(const helpers::InetAddressPtr& address, int port);

		/**
		Connects to remote server at <code>host</code> and <code>port</code>.
		*/
		JSONSocketAppender(const LogString& host, int port);

	protected:
		int getDefaultDelay() const override;

		int getDefaultPort() const override;

	private:
		//  prevent copy and assignment statements
		JSONSocketAppender(const JSONSocketAppender&);
		JSONSocketAppender& operator=(const JSONSocketAppender&);

}; // class JSONSocketAppender

LOG4CXX_PTR_DEF(JSONSocketAppender);

} // namespace net
} // namespace log4cxx

#endif // _LOG4CXX_NET_JSON_SOCKET_APPENDER_H

