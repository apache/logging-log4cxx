/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/
 
#include <log4cxx/logger.h>
#include <log4cxx//helpers/stringhelper.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/helpers/thread.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::xml;

/**
This test program sits in a loop and logs things. Its logging is
configured by a configuration file. Changes to this configuration
file are monitored and when a change occurs, the config file is re-read.
*/
class DelayedLoop
{
	static LoggerPtr logger;

public:
	static void main(int argc, char **argv)
	{
		if(argc == 2) 
		{
			USES_CONVERSION;
			init(A2T(argv[1]));
		}
		else 
		{
			usage(argv[0], "Wrong number of arguments.");
		}

		test();
	}
	
	static void usage(const char * programName, const char * msg)
	{
		std::cout << msg << std::endl;
		std::cout << "Usage: java " << programName <<
				"configFile" << std::endl;
		exit(1);
	}


	static void init(const String& configFile)
	{
		if(StringHelper::endsWith(configFile, _T("xml")))
		{
			DOMConfigurator::configureAndWatch(configFile, 3000);
		} 
		else
		{
			PropertyConfigurator::configureAndWatch(configFile, 3000);
		}
	}

	static void test()
	{
		int i = 0;
		while(true)
		{
			LOG4CXX_DEBUG(logger, _T("MSG ") << i++);
			try
			{
				Thread::sleep(1000);
			} 
			catch(Exception& e)
			{
			}
		}
	}
};

LoggerPtr DelayedLoop::logger = Logger::getLogger(_T("DelayedLoop"));

int main(int argc, char **argv)
{
    int result = EXIT_SUCCESS;
    try
    {
		DelayedLoop::main(argc, argv);
	}
	catch(Exception&)
	{
		result = EXIT_FAILURE;
	}

    return result;
}
