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
<code>millisecondDelay</code> milliseconds.

The periodic task stops trying whenever a connection is established.
It will restart attempting to open a new connection to the server
when a previously open connection is droppped.
 */
class LOG4CXX_EXPORT SocketAppenderSkeleton : public AppenderSkeleton
{
	protected:
		struct SocketAppenderSkeletonPriv;

	public:
		/**
		A unconnected appender sending to \c defaultPort,
		with a retry after \c millisecondDelay when unable to establish a connection.
		*/
		SocketAppenderSkeleton(int defaultPort, int millisecondDelay);

		/**
		Close and shutdown the connection if not already done.
		*/
		~SocketAppenderSkeleton();

		/**
		A remote server at <code>address</code> and <code>port</code>,
		with a retry after \c millisecondDelay when unable to establish a connection.
		*/
		SocketAppenderSkeleton(const helpers::InetAddressPtr& address, int port, int millisecondDelay);

		/**
		A remote server at <code>host</code> and <code>port</code>,
		with a retry after \c millisecondDelay when unable to establish a connection.
		*/
		SocketAppenderSkeleton(const LogString& host, int port, int millisecondDelay);

		using spi::OptionHandler::activateOptions;
		/**
		Connects to the configured <b>RemoteHost</b> and <b>Port</b>.
		*/
		void activateOptions(  ) override;

		/**
		Sends the message that the configured Layout produces from \c event to the output sink.
		*/
		void append( const spi::LoggingEventPtr& event ) override;

		/**
		* Use \c newValue as the name of the server.
		* */
		void setRemoteHost(const LogString& newValue);

		/**
		Returns value of the <b>RemoteHost</b> option.
		*/
		const LogString& getRemoteHost() const;

		/**
		Use \c newValue, which must be a positive integer,
		as the port on which the server is waiting for connections.
		*/
		void setPort(int newValue);

		/**
		Returns value of the <b>Port</b> option.
		*/
		int getPort() const;

		/**
		Use \c millisecondDelay as the number of milliseconds to wait between each
		failed connection attempt to the server.

		Setting this option to zero turns off reconnection capability.
		*/
		void setReconnectionDelay(int millisecondDelay);

		/**
		The value of the <b>ReconnectionDelay</b> option,
		the number of milliseconds to wait between each
		failed connection attempt to the server.
		*/
		int getReconnectionDelay() const;

		/**
		* Use \c newSubclass as the helpers::Socket interface instead of the default implementation.
		* */
		void setSocketSubclass(const LogString& newSubclass);

		/**
		The class name used for the helpers::Socket interface implemention.
		*/
		const LogString& getSocketSubclass() const;

		/**
		\copybrief AppenderSkeleton::setOption()

		Supported options | Supported values | Default value |
		-------------- | ---------------- | --------------- |
		RemoteHost |  (\ref inetAddress "1") | - |
		Port | {int} | (\ref defaultPort "2") |
		SocketSubclass |  (\ref socketSubclass "3") | APRSocket |

		\anchor inetAddress (1) A valid internet address.

		\anchor defaultPort (2) Provided by the derived class.

		\anchor socketSubclass (3) A registered class derived from helpers::Socket.

		\sa AppenderSkeleton::setOption()
		*/
		void setOption(const LogString& option, const LogString& value) override;

	protected:
		SocketAppenderSkeleton(std::unique_ptr<SocketAppenderSkeletonPriv> priv);

		virtual int getDefaultDelay() const = 0;

		virtual int getDefaultPort() const = 0;

	private:

		SocketAppenderSkeleton(const SocketAppenderSkeleton&);
		SocketAppenderSkeleton& operator=(const SocketAppenderSkeleton&);

}; // class SocketAppenderSkeleton
} // namespace net
} // namespace log4cxx

#endif // _LOG4CXX_NET_SOCKET_APPENDER_SKELETON_H

