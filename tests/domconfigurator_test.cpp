#include <stdlib.h>
#include <log4cxx/logger.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/logger.h>
#include <log4cxx/level.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/simplelayout.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/helpers/loglog.h>

#ifdef WIN32
#include <windows.h>
#endif


using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::xml;

int main()
{
	int result = EXIT_SUCCESS;

	try
	{
#ifdef WIN32
		::CoInitialize(0);
		DOMConfigurator::configure(_T("domconfigurator_test.xml"));
		::CoUninitialize();
#else
		DOMConfigurator::configure(_T("domconfigurator_test.xml"));
#endif

		// levels
		LoggerPtr root = Logger::getRootLogger();
		if (root->getLevel() != Level::getDebugLevel())
		{
			throw RuntimeException(_T("incorrect root level !"));
		}

		LoggerPtr sub1 = Logger::getLogger(_T("sub1"));
		if (sub1->getLevel() != Level::getOffLevel())
		{
			throw RuntimeException(_T("incorrect logger sub1 level !"));
		}

		LoggerPtr sub2 = Logger::getLogger(_T("sub2"));
		if (sub2->getLevel() != Level::getInfoLevel())
		{
			throw RuntimeException(_T("incorrect logger sub2 level !"));
		}

		LoggerPtr sub1Sub2 = Logger::getLogger(_T("sub1.sub2"));
		if (sub1Sub2->getLevel() != Level::getErrorLevel())
		{
			throw RuntimeException(_T("incorrect logger sub1.sub2 level !"));
		}

		// additivity
		if (sub1Sub2->getAdditivity())
		{
			throw RuntimeException(_T("incorrect logger sub1.sub2 additivity !"));
		}

		// appenders
		AppenderList appenderList = root->getAllAppenders();
		if (appenderList.empty())
		{
			throw RuntimeException(_T("appender rootAppender does not exist !"));
		}

		ConsoleAppenderPtr rootAppender = appenderList[0];
		if (rootAppender == 0 || rootAppender->getName() != _T("rootAppender"))
		{
			throw RuntimeException(_T("incorrect appender rootAppender!"));
		}

		appenderList = sub1->getAllAppenders();
		if (appenderList.empty())
		{
			throw RuntimeException(_T("appender A1 does not exist !"));
		}

		FileAppenderPtr A1 = appenderList[0];
		if (A1 == 0 || A1->getName() != _T("A1"))
		{
			throw RuntimeException(_T("incorrect appender A1 !"));
		}

		if (A1->getFile() != _T("A1.log"))
		{
			throw RuntimeException(_T("incorrect appender A1 filename !"));
		}

		appenderList = sub2->getAllAppenders();
		if (!appenderList.empty())
		{
			throw RuntimeException(
				_T("logger sub2 should not have any appender !"));
		}

		appenderList = sub1Sub2->getAllAppenders();
		if (appenderList.empty())
		{
			throw RuntimeException(_T("appender A2 does not exist !"));
		}

		ConsoleAppenderPtr A2 = appenderList[0];
		if (A2 == 0 || A2->getName() != _T("A2"))
		{
			throw RuntimeException(_T("incorrect appender A2 !"));
		}

		// layouts
		SimpleLayoutPtr simpleLayout = rootAppender->getLayout();
		if (simpleLayout == 0)
		{
			throw RuntimeException(_T("incorrect appender rootAppender layout !"));
		}

		simpleLayout = A1->getLayout();
		if (simpleLayout == 0)
		{
			throw RuntimeException(_T("incorrect appender A1 layout !"));
		}

		PatternLayoutPtr patternLayout = A2->getLayout();
		if (patternLayout == 0)
		{
			throw RuntimeException(_T("incorrect appender A2 layout !"));
		}

		if (patternLayout->getConversionPattern() != _T("The message '%m' at time %d%n"))
		{
			throw RuntimeException(_T("incorrect appender A2 layout conversion pattern !"));
		}
	}
	catch(Exception& e)
	{
		LogLog::error(_T("Exception raised"), e);
		result = EXIT_FAILURE;
	}

	return result;
}
