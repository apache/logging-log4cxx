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

#ifndef _LOG4CXX_SYSLOG_WRITER_H
#define _LOG4CXX_SYSLOG_WRITER_H


#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/inetaddress.h>

 namespace log4cxx
{
        namespace helpers
        {
                class DatagramSocket;
                typedef helpers::ObjectPtrT<DatagramSocket> DatagramSocketPtr;

                /**
                SyslogWriter is a wrapper around the DatagramSocket class
                it writes text to the specified host on the port 514 (UNIX syslog)
                */
                class LOG4CXX_EXPORT SyslogWriter
                {
                public:
                        SyslogWriter(const LogString& syslogHost);
                        void write(const LogString& string);

                private:
                        LogString syslogHost;
                        InetAddress address;
                        DatagramSocketPtr ds;
                };
        }  // namespace helpers
} // namespace log4cxx

#endif
