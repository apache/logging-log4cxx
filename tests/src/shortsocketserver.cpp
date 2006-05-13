/*
 * Copyright 2003,2005 The Apache Software Foundation.
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

#include <log4cxx/logger.h>
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/helpers/serversocket.h>
#include <log4cxx/mdc.h>
#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/helpers/inetaddress.h>
#include <log4cxx/helpers/socket.h>
#include <log4cxx/net/socketnode.h>

#include "net/socketservertestcase.h"
#include <sstream>
#include <iostream>
#include <stdlib.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::net;

class ShortSocketServer
{
   static LoggerPtr logger;

public:
   static void main(int argc, char **argv)
   {
      int totalTests = 0;
      std::string prefix;

      if (argc == 3)
      {
          totalTests = atoi(argv[1]);
          prefix = argv[2];
      }
      else
      {
         usage(argv[0], "Wrong number of arguments.");
      }

      //
      //  TODO: May need to make another logger hierarchy to
      //     keep this distinct from the log messages the server
      //     is handling
      log4cxx::BasicConfigurator::configure();
      //
      //   using the stream interface since it knows
      //      numeric and encoding conversion
      LoggerPtr logger(Logger::getLogger("shortsocketserver"));
     std::ostringstream os("Listening on port ");
     os << PORT;
     LOG4CXX_INFO(logger, os.str());

     ServerSocket serverSocket(PORT);

      MDC::put("hostID", "shortSocketServer");

      for (int i = 1; i <= totalTests; i++)
      {
         std::ostringstream sbuf(prefix);
         sbuf <<  i  << ".properties";
         PropertyConfigurator::configure(sbuf.str());
         LOG4CXX_INFO(logger, "Waiting to accept a new client.");
         SocketPtr socket = serverSocket.accept();
       LogString msg(socket->getInetAddress()->toString());
       msg.insert(0, LOG4CXX_STR("Connected to client at "));
       LOG4CXX_INFO(logger, msg);
         LOG4CXX_INFO(logger, "Starting new socket node.");
         SocketNode sn(socket, LogManager::getLoggerRepository());
         sn.run();
      }
   }


   static void usage(const char * programName, const char * msg)
   {
      std::cout << msg << std::endl;
      std::cout << "Usage: " << programName;
      std::cout << " totalTests configFilePrefix" << std::endl;
      exit(1);
   }
};

LoggerPtr ShortSocketServer::logger =
   Logger::getLogger("org.apache.log4j.net.ShortSocketServer");

int main(int argc, char **argv)
{
    int result = EXIT_SUCCESS;
    try
    {
      ShortSocketServer::main(argc, argv);
   }
   catch(Exception&)
   {
      result = EXIT_FAILURE;
   }

    return result;
}
