/***************************************************************************
                          sockethubappender.cpp  -  class SocketHubAppender
                             -------------------
    begin                : jeu mai 8 2003
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

#include <log4cxx/net/sockethubappender.h>

#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/socketoutputstream.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/serversocket.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::net;
using namespace log4cxx::spi;

int SocketHubAppender::DEFAULT_PORT = 4560;

SocketHubAppender::~SocketHubAppender()
{
	finalize();
}

SocketHubAppender::SocketHubAppender()
 : port(DEFAULT_PORT), locationInfo(false)
{
}

SocketHubAppender::SocketHubAppender(int port)
 : port(port), locationInfo(false)
{
	startServer();
}

void SocketHubAppender::activateOptions()
{
	startServer();
}

void SocketHubAppender::setOption(const tstring& option,
	const tstring& value)
{
	if (StringHelper::equalsIgnoreCase(option, _T("port")))
	{
		setPort(OptionConverter::toInt(value, DEFAULT_PORT));
	}
	else if (StringHelper::equalsIgnoreCase(option, _T("locationinfo")))
	{
		setLocationInfo(OptionConverter::toBoolean(value, true));
	}
	else
	{
		AppenderSkeleton::setOption(name, value);
	}
}


void SocketHubAppender::close()
{
	synchronized sync(this);

	if(closed)
	{
		return;
	}
	
	LOGLOG_DEBUG(_T("closing SocketHubAppender ") << getName());
	closed = true;
	cleanUp();
	LOGLOG_DEBUG(_T("SocketHubAppender ") << getName() << _T(" closed"));
}

void SocketHubAppender::cleanUp()
{
	// stop the monitor thread
	LOGLOG_DEBUG(_T("stopping ServerSocket"));
	serverMonitor->stopMonitor();
	serverMonitor = 0;
	
	// close all of the connections
	LOGLOG_DEBUG(_T("closing client connections"));
	while (!oosList.empty())
	{
		SocketOutputStreamPtr oos = oosList.at(0);
		if(oos != 0)
		{
			try
			{
				oos->close();
			}
			catch(SocketException& e)
			{
				LogLog::error(_T("could not close oos: "), e);
			}
			
			oosList.erase(oosList.begin());     
		}
	}
}

void SocketHubAppender::append(const spi::LoggingEvent& event)
{

	// if no open connections, exit now
	if(oosList.empty())
	{
		return;
	}
	
/*	// set up location info if requested
	if (locationInfo)
	{
		event.getLocationInformation();	
	} */
	
	// loop through the current set of open connections, appending the event to each
	std::vector<SocketOutputStreamPtr>::iterator it, itEnd = oosList.end();
	while(it != itEnd)
	{ 	
		SocketOutputStreamPtr oos = *it;
		
		// list size changed unexpectedly? Just exit the append.
		if (oos == 0)
		{
			break;
		}
		
		try 
		{
			event.write(oos);
			oos->flush();
			it++;
		}
		catch(SocketException& e)
		{
			// there was an io exception so just drop the connection
			it = oosList.erase(it);
			LOGLOG_DEBUG(_T("dropped connection"));
		}
	}
}

void SocketHubAppender::startServer()
{
	serverMonitor = new ServerMonitor(port, oosList);
}

SocketHubAppender::ServerMonitor::ServerMonitor(int port, const std::vector<helpers::SocketOutputStreamPtr>& oosList)
: port(port), oosList(oosList), keepRunning(true)
{
	monitorThread = new Thread(this);
	monitorThread->start();
}

void SocketHubAppender::ServerMonitor::stopMonitor()
{
	synchronized sync(this);

	if (keepRunning)
	{	
		LogLog::debug(_T("server monitor thread shutting down"));
		keepRunning = false;
		try
		{	
			monitorThread->join();
		}
		catch (InterruptedException e)
		{
			// do nothing?
		}
		
		// release the thread
		monitorThread = 0;
		LogLog::debug(_T("server monitor thread shut down"));
	}
}

void SocketHubAppender::ServerMonitor::run()
{
	ServerSocket * serverSocket = 0;

	try
	{
		serverSocket = new ServerSocket(port);
		serverSocket->setSoTimeout(1000);
	}
	catch (SocketException& e)
	{
		LogLog::error(_T("exception setting timeout, shutting down server socket."), e);
		keepRunning = false;
		return;
	}
	
	try
	{
		serverSocket->setSoTimeout(1000);
	}
	catch (SocketException& e)
	{
		LogLog::error(_T("exception setting timeout, shutting down server socket."), e);
		return;
	}
	
	while (keepRunning)
	{
		SocketPtr socket;
		try
		{
			socket = serverSocket->accept();
		}
		catch (InterruptedIOException& e)
		{
			// timeout occurred, so just loop
		}
		catch (SocketException& e)
		{
			LogLog::error(_T("exception accepting socket, shutting down server socket."), e);
			keepRunning = false;
		}
		catch (IOException& e)
		{
			LogLog::error(_T("exception accepting socket."), e);
		}
		
		// if there was a socket accepted
		if (socket != 0)
		{
			try
			{
				InetAddress remoteAddress = socket->getInetAddress();
				LOGLOG_DEBUG(_T("accepting connection from ") << remoteAddress.getHostName() 
					<< _T(" (") + remoteAddress.getHostAddress() + _T(")"));
				
				// create an ObjectOutputStream
				SocketOutputStreamPtr oos = socket->getOutputStream();
				
				// add it to the oosList.  OK since Vector is synchronized.
				oosList.push_back(oos);
			}
			catch (IOException& e)
			{
				LogLog::error(_T("exception creating output stream on socket."), e);
			}
		}
	}

	delete serverSocket;
}

