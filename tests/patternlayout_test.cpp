#include <stdlib.h>
#include <log4cxx/logger.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/patternlayout.h>
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
		PatternLayoutPtr layout = new PatternLayout();
		layout->setConversionPattern(_T("%-5p [%t]: %m%n"));
		LoggingEvent event(
			Logger::getStaticClass().getName(),
			Logger::getRootLogger(),
			Level::getDebugLevel(),
			_T("debug message"),
			"file.cpp", 
			12
			);
		
		tostringstream result, witness;
		
		witness << _T("DEBUG [") << event.getThreadId()
			<< _T("]: debug message") << std::endl;
//		tcout << witness.str();

		layout->format(result, event);
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