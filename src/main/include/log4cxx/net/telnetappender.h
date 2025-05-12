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

#ifndef _LOG4CXX_NET_TELNET_APPENDER_H
#define _LOG4CXX_NET_TELNET_APPENDER_H

#include <log4cxx/appenderskeleton.h>
#include <log4cxx/helpers/socket.h>

namespace LOG4CXX_NS
{
namespace helpers
{
class ByteBuffer;
}
namespace net
{

/**
The TelnetAppender writes log messages to
clients that connect to the TCP port.

This allows logging output to be monitored using TCP/IP.
To receive log data, use telnet to connect to the configured port number.

TelnetAppender is most useful as a secondary appender,
especially when monitoring a servlet remotely.

If no layout is provided, the log message only is sent to attached client(s).

The \c ReuseAddress option is disabled by default.
Enable it to be able to connect to this appender
immediately after the logging process restarts.

See TelnetAppender::setOption() for the available options.

*/
class LOG4CXX_EXPORT TelnetAppender : public AppenderSkeleton
{
	private:
		static const int DEFAULT_PORT;
		static const int MAX_CONNECTIONS;

	public:
		DECLARE_LOG4CXX_OBJECT(TelnetAppender)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(TelnetAppender)
		LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
		END_LOG4CXX_CAST_MAP()

		TelnetAppender();
		~TelnetAppender();

		/**
		If no layout is provided, sends only the log message to attached client(s).
		*/
		bool requiresLayout() const override;

		/**
		The current encoding value.

		\sa setOption
		 */
		LogString getEncoding() const;
		/**
		Set the encoding to \c value.

		\sa setOption
		 */
		void setEncoding(const LogString& value);


		/**
		\copybrief AppenderSkeleton::activateOptions()

		Create the socket handler and wait for connections.
		*/
		void activateOptions(helpers::Pool& p) override;


		/**
		\copybrief AppenderSkeleton::setOption()

		Supported options | Supported values | Default value
		-------------- | ---------------- | ---------------
		Port | {int} | 23
		MaxConnections | {int} | 20
		Encoding | C,UTF-8,UTF-16,UTF-16BE,UTF-16LE,646,US-ASCII,ISO646-US,ANSI_X3.4-1968,ISO-8859-1,ISO-LATIN-1 | UTF-8
		ReuseAddress | True,False | False

		\sa AppenderSkeleton::setOption()
		*/
		void setOption(const LogString& option, const LogString& value) override;

		/**
		The TCP <b>Port</b> number on which to accept connections.
		*/
		int getPort() const;

		/**
		Use \c newValue as the TCP port number on which to accept connections.
		*/
		void setPort(int newValue);

		/**
		The <b>Hostname</b> on which to accept connections.
		*/
		LogString getHostname() const;

		/**
		Use \c newValue as the Hostname on which to accept connections.
		By default connections are accepted on any network interface device.
		*/
		void setHostname(const LogString& newValue);

		/**
		The number of allowed concurrent connections.

		\sa setOption
		 */
		int getMaxConnections() const;

		/**
		Set the number of allowed concurrent connections to \c newValue.

		\sa setOption
		 */
		void setMaxConnections(int newValue);

		/**
		Use \c newValue for the SO_REUSEADDR option of the socket accepting connections.
		When set to \c true, a telnet client can connect when the socket is in a TIME_WAIT state,
		so log message delivery will resume quickly when a terminated process restarts.

		\sa setOption
		 */
		void setReuseAddress(bool newValue);

		/** Shutdown this appender. */
		void close() override;

	protected:
		/** Send \c event to each connected client.
		*/
		void append(const spi::LoggingEventPtr& event, helpers::Pool& p) override;

	private:
		//   prevent copy and assignment statements
		TelnetAppender(const TelnetAppender&);
		TelnetAppender& operator=(const TelnetAppender&);

		void write(helpers::ByteBuffer&);
		void writeStatus(const helpers::SocketPtr& socket, const LogString& msg, helpers::Pool& p);
		void acceptConnections();

		struct TelnetAppenderPriv;
}; // class TelnetAppender

LOG4CXX_PTR_DEF(TelnetAppender);
} // namespace net
} // namespace log4cxx

#endif // _LOG4CXX_NET_TELNET_APPENDER_H

