#include <stdlib.h>
#include <log4cxx/logger.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/simplelayout.h>
#include <log4cxx/helpers/exception.h>
#include <fstream>

using namespace log4cxx;
using namespace log4cxx::helpers;

int main()
{
	int ret = EXIT_SUCCESS;
	
	try
	{
    	LayoutPtr layout = new SimpleLayout();
    	AppenderPtr consoleAppender =
      		new ConsoleAppender(layout, _T("System.Out"));

		LoggerPtr rootLogger = Logger::getRootLogger();
		rootLogger->addAppender(consoleAppender);
		
		// redirecting stdout to file "result"
		freopen("result", "w", stdout);

		rootLogger->debug(_T("debug message"));
		rootLogger->info(_T("info message"));
		rootLogger->warn(_T("warn message"));
		rootLogger->error(_T("error message"));
		rootLogger->fatal(_T("fatal message"));

		consoleAppender->close();

#ifdef UNICODE
		std::wofstream witness;
#else
		std::ofstream witness;
#endif
		witness.open("witness", std::ios::out|std::ios::trunc);
		witness << _T("DEBUG - debug message") << std::endl;
		witness << _T("INFO - info message") << std::endl;
		witness << _T("WARN - warn message") << std::endl;
		witness << _T("ERROR - error message") << std::endl;
		witness << _T("FATAL - fatal message") << std::endl;
		witness.close();

#ifdef UNICODE
		std::wifstream inr, inw;
#else
		std::ifstream inr, inw;
#endif
		inr.open("result", std::ios::in|std::ios::binary);
		inw.open("witness", std::ios::in|std::ios::binary);
		if (inr.fail() || inw.fail())
		{
			ret = EXIT_FAILURE;
		}
		else
		{
			inr.seekg(0, std::ios_base::end);
			int sizer = inr.tellg();
			inr.seekg(0, std::ios_base::beg);

			inw.seekg(0, std::ios_base::end);
			int sizew = inw.tellg();
			inw.seekg(0, std::ios_base::beg);

			if (sizer != sizew)
			{
				ret = EXIT_FAILURE;
			}
			else
			{
				TCHAR * result = new TCHAR[sizer + 1];
				TCHAR * witness = new TCHAR[sizew + 1];
				memset(result, sizer * sizeof(TCHAR), 0);
				memset(witness, sizew * sizeof(TCHAR), 0);
				inr.read(result, sizer);
				inw.read(witness, sizew);
				result[sizer] = _T('\0');
				witness[sizew] = _T('\0');

				if (memcmp(result, witness, sizer * sizeof(TCHAR)) != 0)
				{
					ret = EXIT_FAILURE;
				}

				delete [] result;
				delete [] witness;

				inr.close();
				inw.close();
			}
		}
	}
	catch(Exception&)
	{
		ret = EXIT_FAILURE;
	}

	return ret;
}
