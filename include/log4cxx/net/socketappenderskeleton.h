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

#ifndef _LOG4CXX_NET_SOCKET_APPENDER_SKELETON_H
#define _LOG4CXX_NET_SOCKET_APPENDER_SKELETON_H

#include <log4cxx/appenderskeleton.h>
#include <log4cxx/helpers/socket.h>
#include <log4cxx/helpers/thread.h>


namespace log4cxx
{
        namespace helpers
        {
                class SocketOutputStream;
                typedef helpers::ObjectPtrT<SocketOutputStream> SocketOutputStreamPtr;
        }

        namespace net
        {

                /**
                 *  Abstract base class for SocketAppender and XMLSocketAppender
                 */
        class LOG4CXX_EXPORT SocketAppenderSkeleton : public AppenderSkeleton
        {
        private:
                log4cxx::helpers::Pool pool;
                /**
                host name
                */
                LogString remoteHost;

                /**
                IP address
                */
                helpers::InetAddress address;

                int port;
                helpers::SocketOutputStreamPtr os;
                int reconnectionDelay;
                bool locationInfo;

        public:
                SocketAppenderSkeleton(int defaultPort, int reconnectionDelay);
                        ~SocketAppenderSkeleton();

                /**
                Connects to remote server at <code>address</code> and <code>port</code>.
                */
                SocketAppenderSkeleton(unsigned long address, int port, int reconnectionDelay);

                /**
                Connects to remote server at <code>host</code> and <code>port</code>.
                */
                SocketAppenderSkeleton(const LogString& host, int port, int reconnectionDelay);

                /**
                Connect to the specified <b>RemoteHost</b> and <b>Port</b>.
                */
                void activateOptions(apr_pool_t* p);


                /**
                * Close this appender.
                *
                * <p>This will mark the appender as closed and call then
                * #cleanUp method.
                * */
                void close();

                /**
                * Drop the connection to the remote host and release the underlying
                * connector thread if it has been created
                * */
                void cleanUp();

                void connect();

                   /**
                * This appender does not use a layout. Hence, this method
                * returns <code>false</code>.
                *
                        */
                bool requiresLayout() const
                        { return false; }


                        void append(const spi::LoggingEventPtr& event, apr_pool_t* p);


                /**
                * The <b>RemoteHost</b> option takes a string value which should be
                * the host name of the server where a
                        * {@link net::SocketNode SocketNode} is running.
                * */
                inline void setRemoteHost(const LogString& host)
                        { address = helpers::InetAddress::getByName(host);
                        remoteHost.assign(host); }

                /**
                Returns value of the <b>RemoteHost</b> option.
                */
                inline const LogString& getRemoteHost() const
                        { return remoteHost; }

                /**
                The <b>Port</b> option takes a positive integer representing
                the port where the server is waiting for connections.
                */
                void setPort(int port)
                        { this->port = port; }

                /**
                Returns value of the <b>Port</b> option.
                */
                int getPort() const
                        { return port; }

                /**
                The <b>LocationInfo</b> option takes a boolean value. If true,
                the information sent to the remote host will include location
                information. By default no location information is sent to the server.
                */
                void setLocationInfo(bool locationInfo)
                        { this->locationInfo = locationInfo; }

                /**
                Returns value of the <b>LocationInfo</b> option.
                */
                bool getLocationInfo() const
                        { return locationInfo; }

                /**
                The <b>ReconnectionDelay</b> option takes a positive integer
                representing the number of milliseconds to wait between each
                failed connection attempt to the server. The default value of
                this option is 30000 which corresponds to 30 seconds.

                <p>Setting this option to zero turns off reconnection
                capability.
                */
                void setReconnectionDelay(int reconnectionDelay)
                        { this->reconnectionDelay = reconnectionDelay; }

                /**
                Returns value of the <b>ReconnectionDelay</b> option.
                */
                int getReconnectionDelay() const
                        { return reconnectionDelay; }

                    void fireConnector();

           protected:
                    /**
                    Set options
                    */
                        void setOption(const LogString& option,
                                const LogString& value, int defaultPort, int defaultDelay);

                        virtual void renderEvent(const spi::LoggingEventPtr& event,
                                helpers::SocketOutputStreamPtr& os,
                                apr_pool_t* p) = 0;

       private:
                   /**
                        The Connector will reconnect when the server becomes available
                        again.  It does this by attempting to open a new connection every
                        <code>reconnectionDelay</code> milliseconds.

                        <p>It stops trying whenever a connection is established. It will
                        restart to try reconnect to the server when previpously open
                        connection is droppped.
                        */

                   helpers::Thread thread;
                    static void* LOG4CXX_THREAD_FUNC monitor(apr_thread_t* thread, void* data);
                        SocketAppenderSkeleton(const SocketAppenderSkeleton&);
                        SocketAppenderSkeleton& operator=(const SocketAppenderSkeleton&);

        }; // class SocketAppenderSkeleton
    } // namespace net
} // namespace log4cxx

#endif // _LOG4CXX_NET_SOCKET_APPENDER_SKELETON_H

