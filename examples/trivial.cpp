/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#include <stdlib.h>
#include <log4cxx/logger.h>
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/ndc.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

int main()
{
    int result = EXIT_SUCCESS;
    try
    {
		BasicConfigurator::configure();
 		LoggerPtr rootLogger = Logger::getRootLogger();

		NDC::push(_T("trivial context"));

		rootLogger->debug(_T("debug message"));
		rootLogger->info(_T("info message"));
		rootLogger->warn(_T("warn message"));
		rootLogger->error(_T("error message"));
		rootLogger->fatal(_T("fatal message"));
	}
	catch(Exception&)
	{
		result = EXIT_FAILURE;
	}

    return result;
}
