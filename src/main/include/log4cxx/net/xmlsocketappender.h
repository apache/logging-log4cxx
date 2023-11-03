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
#include <log4cxx/helpers/writer.h>

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

<p>XMLSocketAppender has the following properties:

- The event will be logged with the same time stamp,
NDC, location info as if it were logged locally by
the client.

- Remote logging uses the TCP protocol. Consequently, if
the server is reachable, then log events will eventually arrive
at the server.

- If the remote server is down, the logging requests are
simply dropped. However, if and when the server comes back up,
then event transmission is resumed transparently. This
transparent reconneciton is performed by a <em>connector</em>
thread which periodically attempts to connect to the server.

- Logging events are automatically <em>buffered</em> by the
native TCP implementation. This means that if the link to server
is slow but still faster than the rate of (log) event production
by the client, the client will not be affected by the slow
network connection. However, if the network connection is slower
then the rate of event production, then the client can only
progress at the network rate. In particular, if the network link
to the the server is down, the client will be blocked.
@n @n On the other hand, if the network link is up, but the server
is down, the client will not be blocked when making log requests
but the log events will be lost due to server unavailability.

- Even if an <code>XMLSocketAppender</code> is no longer
attached to any logger, it will not be destroyed in
the presence of a connector thread. A connector thread exists
only if the connection to the server is down. To avoid this
destruction problem, you should #close the the
<code>XMLSocketAppender</code> explicitly. See also next item.
@n @n Long lived applications which create/destroy many
<code>XMLSocketAppender</code> instances should be aware of this
destruction problem. Most other applications can safely
ignore it.

- If the application hosting the <code>XMLSocketAppender</code>
exits before the <code>XMLSocketAppender</code> is closed either
explicitly or subsequent to destruction, then there might
be untransmitted data in the pipe which might be lost.
@n @n To avoid lost data, it is usually sufficient to
#close the <code>XMLSocketAppender</code> either explicitly or by
calling the LogManager#shutdown method
before exiting the application.
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

		/**
		Unused
		*/
		static const int MAX_EVENT_LEN;

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
		XMLSocketAppender(helpers::InetAddressPtr address, int port);

		/**
		Connects to remote server at <code>host</code> and <code>port</code>.
		*/
		XMLSocketAppender(const LogString& host, int port);


	protected:
		void setSocket(LOG4CXX_NS::helpers::SocketPtr& socket, helpers::Pool& p) override;

		void cleanUp(helpers::Pool& p) override;

		int getDefaultDelay() const override;

		int getDefaultPort() const override;

		void append(const spi::LoggingEventPtr& event, helpers::Pool& pool) override;

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

