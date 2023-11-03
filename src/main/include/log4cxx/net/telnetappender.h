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
#include <log4cxx/helpers/serversocket.h>
#include <thread>
#include <vector>
#include <log4cxx/helpers/charsetencoder.h>

namespace LOG4CXX_NS
{
namespace helpers
{
class ByteBuffer;
}
namespace net
{
typedef LOG4CXX_NS::helpers::SocketPtr Connection;
LOG4CXX_LIST_DEF(ConnectionList, Connection);

/**
<p>The TelnetAppender is a log4cxx appender that specializes in
writing to a read-only socket.  The output is provided in a
telnet-friendly way so that a log can be monitored over TCP/IP.
Clients using telnet connect to the socket and receive log data.
This is handy for remote monitoring, especially when monitoring a
servlet.

<p>Here is a list of the available configuration options:

<table border=1>
<tr>
<td align=center><b>Name</b></td>
<td align=center><b>Requirement</b></td>
<td align=center><b>Description</b></td>
<td align=center><b>Sample Value</b></td>
</tr>

<tr>
<td>Port</td>
<td>optional</td>
<td>This parameter determines the port to use for announcing log events.  The default port is 23 (telnet).</td>
<td>5875</td>
</table>
*/
class LOG4CXX_EXPORT TelnetAppender : public AppenderSkeleton
{
		class SocketHandler;
		friend class SocketHandler;
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
		This appender requires a layout to format the text to the
		attached client(s). */
		bool requiresLayout() const override
		{
			return true;
		}

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
		Encoding | C,UTF-8,UTF-16,UTF-16BE,UTF-16LE,646,US-ASCII,ISO646-US,ANSI_X3.4-1968,ISO-8859-1,ISO-LATIN-1 | UTF-8

		\sa AppenderSkeleton::setOption()
		*/
		void setOption(const LogString& option, const LogString& value) override;

		/**
		Returns value of the <b>Port</b> option.
		*/
		int getPort() const;

		/**
		The <b>Port</b> option takes a positive integer representing
		the port where the server is waiting for connections.
		*/
		void setPort(int port1);


		/** shuts down the appender. */
		void close() override;

	protected:
		/** Handles a log event.  For this appender, that means writing the
		message to each connected client.  */
		void append(const spi::LoggingEventPtr& event, helpers::Pool& p) override;

		//---------------------------------------------------------- SocketHandler:

	private:
		//   prevent copy and assignment statements
		TelnetAppender(const TelnetAppender&);
		TelnetAppender& operator=(const TelnetAppender&);

		void write(LOG4CXX_NS::helpers::ByteBuffer&);
		void writeStatus(const LOG4CXX_NS::helpers::SocketPtr& socket, const LogString& msg, LOG4CXX_NS::helpers::Pool& p);
		void acceptConnections();

		struct TelnetAppenderPriv;
}; // class TelnetAppender

LOG4CXX_PTR_DEF(TelnetAppender);
} // namespace net
} // namespace log4cxx

#endif // _LOG4CXX_NET_TELNET_APPENDER_H

