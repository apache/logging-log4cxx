#include <stdlib.h>
#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/logger.h>
#include <log4cxx/level.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/simplelayout.h>
#include <log4cxx/patternlayout.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

int main(int argc, char *argv[])
{
	int result = EXIT_SUCCESS;

	try
	{
		if (argc > 1)
		{
			USES_CONVERSION;
			PropertyConfigurator::configure(A2T(argv[1]));
		}
		else
		{
			PropertyConfigurator::configure(_T("propertyconfigurator_test.properties"));
		}

		// levels
		LoggerPtr root = Logger::getRootLogger();
		if (root->getLevel() != Level::getDebugLevel())
		{
			throw RuntimeException();
		}

		LoggerPtr sub1 = Logger::getLogger(_T("sub1"));
		if (sub1->getLevel() != Level::getOffLevel())
		{
			throw RuntimeException();
		}

		LoggerPtr sub2 = Logger::getLogger(_T("sub2"));
		if (sub2->getLevel() != Level::getInfoLevel())
		{
			throw RuntimeException();
		}

		LoggerPtr sub1Sub2 = Logger::getLogger(_T("sub1.sub2"));
		if (sub1Sub2->getLevel() != Level::getErrorLevel())
		{
			throw RuntimeException();
		}

		// additivity
		if (sub1Sub2->getAdditivity())
		{
			throw RuntimeException();
		}

		// appenders
		AppenderList appenderList = root->getAllAppenders();
		if (appenderList.empty())
		{
			throw RuntimeException();
		}

		ConsoleAppenderPtr rootAppender = appenderList[0];
		if (rootAppender == 0 || rootAppender->getName() != _T("rootAppender"))
		{
			throw RuntimeException();
		}

		appenderList = sub1->getAllAppenders();
		if (appenderList.empty())
		{
			throw RuntimeException();
		}

		FileAppenderPtr A1 = appenderList[0];
		if (A1 == 0 || A1->getName() != _T("A1"))
		{
			throw RuntimeException();
		}

		if (A1->getFile() != _T("A1.log"))
		{
			throw RuntimeException();
		}

		appenderList = sub2->getAllAppenders();
		if (!appenderList.empty())
		{
			throw RuntimeException();
		}

		appenderList = sub1Sub2->getAllAppenders();
		if (appenderList.empty())
		{
			throw RuntimeException();
		}

		ConsoleAppenderPtr A2 = appenderList[0];
		if (A2 == 0 || A2->getName() != _T("A2"))
		{
			throw RuntimeException();
		}

		// layouts
		SimpleLayoutPtr simpleLayout = rootAppender->getLayout();
		if (simpleLayout == 0)
		{
			throw RuntimeException();
		}

		simpleLayout = A1->getLayout();
		if (simpleLayout == 0)
		{
			throw RuntimeException();
		}

		PatternLayoutPtr patternLayout = A2->getLayout();
		if (patternLayout == 0)
		{
			throw RuntimeException();
		}

		if (patternLayout->getConversionPattern() != _T("The message '%m' at time %d%n"))
		{
			throw RuntimeException();
		}
	}
	catch(Exception&)
	{
		result = EXIT_FAILURE;
	}

	return result;
}
