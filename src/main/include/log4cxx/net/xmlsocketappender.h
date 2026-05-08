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

#ifndef _LOG4CXX_NET_XML_SOCKET_APPENDER_H
#define _LOG4CXX_NET_XML_SOCKET_APPENDER_H

#include <log4cxx/net/socketappenderskeleton.h>

namespace LOG4CXX_NS
{
namespace net
{

/**
Sends spi::LoggingEvent elements
to a remote a log server, usually in XML format.

Here is an example configuration that writes JSON to the
<a href="https://docs.fluentbit.io/manual/pipeline/inputs/tcp">TCP input plugin of a fluent-bit log server</a>
running on the same system as the application:
~~~{.xml}
<log4j:configuration xmlns:log4j="http://jakarta.apache.org/log4j/">
<appender name="A1" class="XMLSocketAppender">
  <param name="RemoteHost" value="localhost" />
  <param name="Port"       value="5170" />
  <layout class="JSONLayout"/>
</appender>
<root>
  <priority value ="INFO" />
  <appender-ref ref="A1" />
</root>
</log4j:configuration>
~~~

See \ref socket_appender_properties "SocketAppenderSkeleton" for more information on the behaviour this appender.
*/

class LOG4CXX_EXPORT XMLSocketAppender : public SocketAppenderSkeleton
{
	public:
		/**
		The default port number of remote logging server (4560).
		*/
		static int DEFAULT_PORT;

		/**
		The default reconnection delay (30000 milliseconds or 30 seconds).
		*/
		static int DEFAULT_RECONNECTION_DELAY;

#if LOG4CXX_ABI_VERSION <= 15
		/**
		Unused
		*/
		static const int MAX_EVENT_LEN;
#endif

		DECLARE_LOG4CXX_OBJECT(XMLSocketAppender)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(XMLSocketAppender)
		LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
		END_LOG4CXX_CAST_MAP()

		XMLSocketAppender();
		~XMLSocketAppender();

		/**
		Connects to remote server at <code>address</code> and <code>port</code>.
		*/
#if LOG4CXX_ABI_VERSION <= 15
		XMLSocketAppender(helpers::InetAddressPtr address, int port);
#else
		XMLSocketAppender(const helpers::InetAddressPtr& address, int port);
#endif

		/**
		Connects to remote server at <code>host</code> and <code>port</code>.
		*/
		XMLSocketAppender(const LogString& host, int port);

		using SocketAppenderSkeleton::activateOptions;

#if 15 < LOG4CXX_ABI_VERSION
		/**
		* This appender has a default layout.
		* @returns false
		*/
		bool requiresLayout() const override
		{
			return false;
		}
#endif

	protected:
#if LOG4CXX_ABI_VERSION <= 15
		/**
		@deprecated This method will be removed in a future version.
		*/
		void setSocket(LOG4CXX_NS::helpers::SocketPtr& socket, helpers::Pool& p) override;

		/**
		@deprecated This method will be removed in a future version.
		*/
		void cleanUp(helpers::Pool& p) override;
#endif
		int getDefaultDelay() const override;

		int getDefaultPort() const override;

		void append( LOG4CXX_APPEND_FORMAL_PARAMETERS ) override;

	private:
		//  prevent copy and assignment statements
		XMLSocketAppender(const XMLSocketAppender&);
		XMLSocketAppender& operator=(const XMLSocketAppender&);

		struct XMLSocketAppenderPriv;
}; // class XMLSocketAppender

LOG4CXX_PTR_DEF(XMLSocketAppender);

} // namespace net
} // namespace log4cxx

#endif // _LOG4CXX_NET_XML_SOCKET_APPENDER_H

