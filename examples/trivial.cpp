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
