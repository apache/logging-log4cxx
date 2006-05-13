/*
 * Copyright 2003,2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _LOG4CXX_NET_SOCKET_APPENDER_H
#define _LOG4CXX_NET_SOCKET_APPENDER_H

#include <log4cxx/net/socketappenderskeleton.h>

namespace log4cxx
{
        namespace net
        {
                class LOG4CXX_EXPORT SocketAppender;
                typedef helpers::ObjectPtrT<SocketAppender> SocketAppenderPtr;

        /**
        Sends {@link spi::LoggingEvent LoggingEvent} objects to a remote a log server,
        usually a {@link net::SocketNode SocketNode}.

        <p>The SocketAppender has the following properties:

        - If sent to a {@link net::SocketNode SocketNode}, remote logging
                is non-intrusive as far as the log event is concerned. In other
        words, the event will be logged with the same time stamp, {@link
        NDC NDC}, location info as if it were logged locally by
        the client.

        - SocketAppenders do not use a layout. They ship a
        serialized {@link spi::LoggingEvent LoggingEvent} object
                to the server side.

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

        - Even if a <code>SocketAppender</code> is no longer
        attached to any logger, it will not be destroyed in
        the presence of a connector thread. A connector thread exists
        only if the connection to the server is down. To avoid this
        destruction problem, you should #close the the
        <code>SocketAppender</code> explicitly. See also next item.
        @n @n Long lived applications which create/destroy many
        <code>SocketAppender</code> instances should be aware of this
        destruction problem. Most other applications can safely
        ignore it.

        - If the application hosting the <code>SocketAppender</code>
                exits before the <code>SocketAppender</code> is closed either
        explicitly or subsequent to destruction, then there might
        be untransmitted data in the pipe which might be lost.
        @n @n To avoid lost data, it is usually sufficient to
        #close the <code>SocketAppender</code> either explicitly or by
        calling the LogManager#shutdown method
        before exiting the application.
        */

        class LOG4CXX_EXPORT SocketAppender : public SocketAppenderSkeleton
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

                        DECLARE_LOG4CXX_OBJECT(SocketAppender)
                        BEGIN_LOG4CXX_CAST_MAP()
                                LOG4CXX_CAST_ENTRY(SocketAppender)
                                LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
                        END_LOG4CXX_CAST_MAP()

                SocketAppender();
                        ~SocketAppender();

                /**
                Connects to remote server at <code>address</code> and <code>port</code>.
                */
                SocketAppender(helpers::InetAddressPtr& address, int port);

                /**
                Connects to remote server at <code>host</code> and <code>port</code>.
                */
                SocketAppender(const LogString& host, int port);


                        /**
                     *Set options
                     */
                        virtual void setOption(const LogString& option,
                                const LogString& value) {
                                SocketAppenderSkeleton::setOption(option, value, DEFAULT_PORT, DEFAULT_RECONNECTION_DELAY);
                        }


                /**
                * The SocketAppender does not use a layout. Hence, this method
                * returns <code>false</code>.
                * */
                bool requiresLayout() const
                        { return false; }

                protected:
                        virtual void renderEvent(const spi::LoggingEventPtr& event,
                                helpers::SocketOutputStreamPtr& os,
                                log4cxx::helpers::Pool& p);



        }; // class SocketAppender
    } // namespace net
} // namespace log4cxx

#endif // _LOG4CXX_NET_SOCKET_APPENDER_H

