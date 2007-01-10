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

#include <apr_general.h>
#include <apr_thread_proc.h>

#include <log4cxx/portability.h>

#include <log4cxx/logger.h>
#include <log4cxx/helpers/serversocket.h>
#include <log4cxx/helpers/socket.h>
#include <log4cxx/net/socketnode.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/helpers/thread.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/stringhelper.h>
#include <iostream>
#include <log4cxx/stream.h>

using namespace log4cxx;
using namespace log4cxx::xml;
using namespace log4cxx::net;
using namespace log4cxx::helpers;

int port = 0;

void usage(const std::string& msg)
{
        std::cout << msg << std::endl;
        std::cout << "Usage: simpleocketServer port configFile" << std::endl;
}

void init(const std::string& portStr, const std::string& configFile)
{
        port = atol(portStr.c_str());

        // tests if configFile ends with ".xml"
        if (configFile.length() > 4 &&
              configFile.substr(configFile.length() -4) == ".xml")
        {
                DOMConfigurator::configure(configFile);
        }
        else
        {
                PropertyConfigurator::configure(configFile);
        }
}

void* LOG4CXX_THREAD_FUNC runSocket(log4cxx_thread_t* /* thread */, void* data) {
  SocketNode* node = (SocketNode*) data;
  node->run();
  delete node;
  return 0;
}

int main(int argc, const char * const argv[])
{
        apr_app_initialize(&argc, &argv, NULL);
        if(argc == 3)
        {
                init(argv[1], argv[2]);
        }
        else
        {
                usage("Wrong number of arguments.");
                return 1;
        }

        try
        {
                LoggerPtr logger = Logger::getLogger("SimpleSocketServer");
                log4cxx::logstream logstream(logger, Level::INFO);

                logstream << "Listening on port " << port;


                ServerSocket serverSocket(port);

                while(true)
                {
                        logstream << "Waiting to accept a new client.";
                        SocketPtr socket = serverSocket.accept();

                        logstream << "Connected to client at "
                                << socket->getInetAddress()->toString();
                        logstream << "Starting new socket node.";

                        Thread * thread = new Thread();
                        SocketNode* node = new SocketNode(socket,
                                LogManager::getLoggerRepository());
                        thread->run(runSocket, node);
                }
        }
        catch(SocketException& e)
        {
                std::cout << "SocketException: " << e.what() << std::endl;
        }

        apr_terminate();
        return 0;
}

