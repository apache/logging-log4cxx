/***************************************************************************
                          simplesocketserver.cpp  -  description
                             -------------------
    begin                : ven mai 9 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#include <log4cxx/logger.h>
#include <log4cxx/helpers/serversocket.h>
#include <log4cxx/helpers/socket.h>
#include <log4cxx/net/socketnode.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/helpers/thread.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/level.h>

#ifdef WIN32
#include <windows.h>
#endif

using namespace log4cxx;
using namespace log4cxx::xml;
using namespace log4cxx::net;
using namespace log4cxx::helpers;

int port = 0;

void usage(const tstring& msg)
{
	tcout << msg << std::endl;
	tcout << _T("Usage: simpleocketServer port configFile") << std::endl;
}

void init(const tstring& portStr, const tstring& configFile)
{
	USES_CONVERSION;
	port = ttol(portStr.c_str());

	DOMConfigurator domconfigurator;
#ifdef WIN32
	::CoInitialize(0);
	domconfigurator.doConfigure(configFile);
	::CoUninitialize();
#else
	tcout << _T("domconfigurator.doConfigure") << std::endl;
	domconfigurator.doConfigure(configFile);
#endif
}

int main(int argc, char * argv[])
{
	if(argc == 3)
	{
		USES_CONVERSION;
		init(A2T(argv[1]), A2T(argv[2]));
	}
	else
	{
		USES_CONVERSION;
		init(_T("4560"), _T("logconfig.xml"));
//		usage(_T("Wrong number of arguments."));
//		return 1;
	}

	try
	{
		LoggerPtr logger = Logger::getLogger(_T("SimpleSocketServer"));
		
		LOG4CXX_INFO(logger, _T("Listening on port ") << port);
	
		ServerSocket serverSocket(port);
		while(true)
		{
			LOG4CXX_INFO(logger, _T("Waiting to accept a new client."));
			SocketPtr socket = serverSocket.accept();
			
			LOG4CXX_INFO(logger, _T("Connected to client at ")
				<< socket->getInetAddress().toString());
			LOG4CXX_INFO(logger, _T("Starting new socket node."));
			
			Thread * thread = new Thread(new SocketNode(socket,
				LogManager::getLoggerRepository()));
			thread->start();
		}
	}
	catch(SocketException& e)
	{
		tcout << _T("SocketException: ") << e.getMessage() << std::endl;
	}

	return 0;
}

