#include <stdlib.h>
#include <log4cxx/logger.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/ttcclayout.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/level.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

int main()
{
	int ret = EXIT_SUCCESS;
	
	try
	{
		TTCCLayoutPtr layout = new TTCCLayout();
		LoggingEvent event(
			Logger::getStaticClass().getName(),
			Logger::getRootLogger(),
			Level::getDebugLevel(),
			_T("debug message"),
			"file.cpp", 
			12
			);
		
		tostringstream result, witness;

		layout->formatDate(witness, event);
		witness << _T("[")
			<< event.getThreadId()
			<< _T("] DEBUG root - debug message")
			<< std::endl;

		layout->format(result, event);

//		tcout << witness.str();
//		tcout << result.str();

		if (witness.str() != result.str())
		{
			ret = EXIT_FAILURE;
		}
	}
	catch(Exception&)
	{
		ret = EXIT_FAILURE;
	}
	
	return ret;
}
