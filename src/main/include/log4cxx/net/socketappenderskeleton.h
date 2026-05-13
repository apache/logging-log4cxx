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

#ifndef _LOG4CXX_NET_SOCKET_APPENDER_SKELETON_H
#define _LOG4CXX_NET_SOCKET_APPENDER_SKELETON_H

#include <log4cxx/appenderskeleton.h>
#include <log4cxx/helpers/inetaddress.h>
#if LOG4CXX_ABI_VERSION <= 15
#include <log4cxx/helpers/socket.h>
#endif


namespace LOG4CXX_NS
{

namespace net
{

/**
Abstract base class that sends spi::LoggingEvent elements to a remote server.

\anchor socket_appender_properties
This appender has the following properties:

- The event will be logged with the same time stamp,
NDC, location info as if it were logged locally by
the client.

- Remote logging uses the TCP protocol,
so if the server is reachable,
log events will eventually arrive at the server.

- If the remote server is down, the logging requests are simply dropped.
However, if and when the server comes back up,
then event transmission is resumed transparently.
This transparent reconneciton is performed by a <em>connector</em>
task which periodically attempts to connect to the server.

- Logging events are automatically <em>buffered</em> by the
native TCP implementation. This means that if the link to server
is slow but still faster than the rate of (log) event production
by the client, the client will not be affected by the slow
network connection. However, if the network connection is slower
then the rate of event production, then the client can only
progress at the network rate. In particular, if the network link
to the the server is down, the client will be blocked.
On the other hand, if the network link is up, but the server
is down, the client will not be blocked when making log requests
but the log events will be lost due to server unavailability.

- If the application hosting this appender exits before it is closed,
either explicitly or subsequent to destruction,
then there might be untransmitted data in the pipe which might be lost.

To avoid lost data, it is usually sufficient to
#close the appender either explicitly or by
calling the LogManager#shutdown method
before exiting the application.

A periodic task will connect when the server becomes available.
It does this by attempting to open a new connection every
<code>reconnectionDelay</code> milliseconds.

The periodic task stops trying whenever a connection is established.
It will restart attempting to open a new connection to the server
when a previously open connection is droppped.
 */
class LOG4CXX_EXPORT SocketAppenderSkeleton : public AppenderSkeleton
{
	protected:
		struct SocketAppenderSkeletonPriv;

	public:
		SocketAppenderSkeleton(int defaultPort, int reconnectionDelay);
		~SocketAppenderSkeleton();

		/**
		Connects to remote server at <code>address</code> and <code>port</code>.
		*/
#if LOG4CXX_ABI_VERSION <= 15
		SocketAppenderSkeleton(helpers::InetAddressPtr address, int port, int reconnectionDelay);
#else
		SocketAppenderSkeleton(const helpers::InetAddressPtr& address, int port, int reconnectionDelay);
#endif
		/**
		Connects to remote server at <code>host</code> and <code>port</code>.
		*/
		SocketAppenderSkeleton(const LogString& host, int port, int reconnectionDelay);

		using spi::OptionHandler::activateOptions;
		/**
		\copybrief AppenderSkeleton::activateOptions()

		Connects to the specified <b>RemoteHost</b> and <b>Port</b>.
		*/
		void activateOptions( LOG4CXX_ACTIVATE_OPTIONS_FORMAL_PARAMETERS ) override;

		void close() override;

#if LOG4CXX_ABI_VERSION <= 15
		/**
		* This appender does not use a layout. Hence, this method
		* returns <code>false</code>.
		*
		     */
		bool requiresLayout() const override
		{
			return false;
		}
#endif
		/**
		* The <b>RemoteHost</b> option takes a string value which should be
		* the host name of the server where a
		* Apache Chainsaw or compatible is running.
		* */
		void setRemoteHost(const LogString& host);

		/**
		Returns value of the <b>RemoteHost</b> option.
		*/
		const LogString& getRemoteHost() const;

		/**
		The <b>Port</b> option takes a positive integer representing
		the port where the server is waiting for connections.
		*/
		void setPort(int port1);

		/**
		Returns value of the <b>Port</b> option.
		*/
		int getPort() const;

		/**
		The <b>LocationInfo</b> option takes a boolean value. If true,
		the information sent to the remote host will include location
		information. By default no location information is sent to the server.
		*/
		void setLocationInfo(bool locationInfo1);

		/**
		Returns value of the <b>LocationInfo</b> option.
		*/
		bool getLocationInfo() const;

		/**
		The <b>ReconnectionDelay</b> option takes a positive integer
		representing the number of milliseconds to wait between each
		failed connection attempt to the server. The default value of
		this option is 30000 which corresponds to 30 seconds.

		<p>Setting this option to zero turns off reconnection
		capability.
		*/
		void setReconnectionDelay(int reconnectionDelay1);

		/**
		Returns value of the <b>ReconnectionDelay</b> option.
		*/
		int getReconnectionDelay() const;

#if LOG4CXX_ABI_VERSION <= 15
		/**
		@deprecated This method will be removed in a future version.
		*/
		void fireConnector();
#else
		/**
		* Use \c newSubclass as the helpers::Socket interface instead of the default implementation.
		* */
		void setSocketSubclass(const LogString& newSubclass);

		/**
		The class name used for the helpers::Socket interface implemention.
		*/
		const LogString& getSocketSubclass() const;
#endif

		/**
		\copybrief AppenderSkeleton::setOption()

		Supported options | Supported values | Default value |
		-------------- | ---------------- | --------------- |
		RemoteHost |  (\ref inetAddress "1") | - |
		Port | {int} | (\ref defaultPort "2") |
		LocationInfo | True,False | False |
		SocketSubclass |  (\ref socketSubclass "3") | APRSocket |

		\anchor inetAddress (1) A valid internet address.

		\anchor defaultPort (2) Provided by the derived class.

		\anchor socketSubclass (3) A registered class derived from helpers::Socket.

		\sa AppenderSkeleton::setOption()
		*/
		void setOption(const LogString& option, const LogString& value) override;

	protected:
		SocketAppenderSkeleton(std::unique_ptr<SocketAppenderSkeletonPriv> priv);

#if LOG4CXX_ABI_VERSION <= 15
		/**
		@deprecated This method will be removed in a future version.
		*/
		virtual void setSocket(helpers::SocketPtr& socket, helpers::Pool& p) = 0;

		/**
		@deprecated This method will be removed in a future version.
		*/
		virtual void cleanUp(LOG4CXX_NS::helpers::Pool& p) = 0;
#endif
		virtual int getDefaultDelay() const = 0;

		virtual int getDefaultPort() const = 0;

	private:

		SocketAppenderSkeleton(const SocketAppenderSkeleton&);
		SocketAppenderSkeleton& operator=(const SocketAppenderSkeleton&);

}; // class SocketAppenderSkeleton
} // namespace net
} // namespace log4cxx

#endif // _LOG4CXX_NET_SOCKET_APPENDER_SKELETON_H

