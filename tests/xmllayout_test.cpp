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
	int result = EXIT_SUCCESS;
	
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
		tostringstream result, witness;
		layout->setLocationInfo(false);

		witness << _T("<log4j:event logger=\"root\" timestamp=\"")
			<< (unsigned long)event.getTimeStamp() << _T("000")
			<< _T("\" level=\"DEBUG\" thread=\"")
			<< event.getThreadId() << _T("\">\r\n")
			<< _T("<log4j:message><![CDATA[debug message]]></log4j:message>\r\n")
			<< _T("</log4j:event>\r\n\r\n");

		layout->format(result, event);

//		tcout << witness.str();
//		tcout << result.str();

		if (witness.str() != result.str())
		{
			return EXIT_FAILURE;
		}

		// locationInfo = true;
		tostringstream result2, witness2;
		layout->setLocationInfo(true);

		witness2 << _T("<log4j:event logger=\"root\" timestamp=\"")
			<< (unsigned long)event.getTimeStamp() << _T("000")
			<< _T("\" level=\"DEBUG\" thread=\"")
			<< event.getThreadId() << _T("\">\r\n")
			<< _T("<log4j:message><![CDATA[debug message]]></log4j:message>\r\n")
			<< _T("<log4j:locationInfo file=\"file.cpp\" line=\"12\"/>\r\n")
			<< _T("</log4j:event>\r\n\r\n");

		layout->format(result2, event);

//		tcout << witness2.str();
//		tcout << result2.str();

		if (witness2.str() != result2.str())
		{
			return EXIT_FAILURE;
		}
	}
	catch(Exception&)
	{
		result = EXIT_FAILURE;
	}
	
	return result;
}
