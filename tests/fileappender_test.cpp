#include <stdlib.h>
#include <log4cxx/logger.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/simplelayout.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

int main()
{
	int ret = EXIT_SUCCESS;
	
	try
	{
		LayoutPtr layout = new SimpleLayout();
		
		FileAppender *fileAppender =
			new FileAppender(layout, _T("result"), false);
		
		LoggerPtr rootLogger = Logger::getRootLogger();
		rootLogger->addAppender(fileAppender);
		
		rootLogger->debug(_T("debug message"));
		rootLogger->info(_T("info message"));
		rootLogger->warn(_T("warn message"));
		rootLogger->error(_T("error message"));
		rootLogger->fatal(_T("fatal message"));

		fileAppender->close();

		std::ofstream witness("witness", std::ios::out|std::ios::trunc);
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
				unsigned char * result = new unsigned char[sizer];
				unsigned char * witness = new unsigned char[sizer];
				memset(result, (sizer) * sizeof(TCHAR), 0);
				memset(witness, (sizer) * sizeof(TCHAR), 0);
				inr.read((TCHAR *)result, sizer);
				inw.read((TCHAR *)witness, sizer);

				if (memcmp(result, witness, sizer) != 0)
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
