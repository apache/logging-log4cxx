#include <stdlib.h>
#include <log4cxx/logger.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/htmllayout.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/iso8601dateformat.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

int main()
{
	int result = EXIT_SUCCESS;
	
	try
	{
		HTMLLayoutPtr layout = new HTMLLayout();
		LoggingEvent event(
			Logger::getStaticClass().getName(),
			Logger::getRootLogger(),
			Level::getDebugLevel(),
			_T("debug message"),
			"file.cpp", 
			12
			);
		
		tostringstream result, witness;
		
		witness << std::endl << _T("<tr>") << std::endl << _T("<td>");
		ISO8601DateFormat().format(witness, event.getTimeStamp());
		witness << _T("</td>") << std::endl
			<< _T("<td title=\"") << event.getThreadId()
			<< _T(" thread\">") << event.getThreadId()
			<< _T("</td>") << std::endl
			<< _T("<td title=\"Level\"><font color=\"#339933\">DEBUG</font></td>")
			<< std::endl
			<< _T("<td title=\"root category\">root</td>") << std::endl
			<< _T("<td title=\"Message\">debug message</td>") << std::endl
			<< _T("</tr>") << std::endl;
		
		layout->format(result, event);
		
//		tcout << witness.str();
//		tcout << result.str();
		
		if (witness.str() != result.str())
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
