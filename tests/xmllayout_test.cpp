#include <stdlib.h>
#include <log4cxx/xml/xmllayout.h>
#include <log4cxx/logger.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/level.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::xml;
using namespace log4cxx::spi;

int main()
{
	int ret = EXIT_SUCCESS;
	
	try
	{
		XMLLayoutPtr layout = new XMLLayout();
		LoggingEvent event(
			Logger::getStaticClass().getName(),
			Logger::getRootLogger(),
			Level::getDebugLevel(),
			_T("debug message"),
			"file.cpp", 
			12
			);

		// locationInfo = false;
		StringBuffer result, witness;
		layout->setLocationInfo(false);

		witness << _T("<log4j:event logger=\"root\" timestamp=\"")
			<< event.getTimeStamp()
			<< _T("\" level=\"DEBUG\" thread=\"")
			<< event.getThreadId() << _T("\">") << std::endl
			<< _T("<log4j:message><![CDATA[debug message]]></log4j:message>") << std::endl
			<< _T("</log4j:event>") << std::endl;

		layout->format(result, event);

//		tcout << witness.str();
//		tcout << result.str();

		if (witness.str() != result.str())
		{
			ret = EXIT_FAILURE;
		}

		// locationInfo = true;
		StringBuffer result2, witness2;
		layout->setLocationInfo(true);

		witness2 << _T("<log4j:event logger=\"root\" timestamp=\"")
			<< event.getTimeStamp()
			<< _T("\" level=\"DEBUG\" thread=\"")
			<< event.getThreadId() << _T("\">") << std::endl
			<< _T("<log4j:message><![CDATA[debug message]]></log4j:message>") << std::endl
			<< _T("<log4j:locationInfo file=\"file.cpp\" line=\"12\"/>") << std::endl
			<< _T("</log4j:event>") << std::endl;

		layout->format(result2, event);

//		tcout << witness2.str();
//		tcout << result2.str();

		if (witness2.str() != result2.str())
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
