#include <stdlib.h>
#include <log4cxx/logger.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/simplelayout.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

int main()
{
  int result = EXIT_SUCCESS;

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
  }
  catch(Exception&)
  {
    result = EXIT_FAILURE;
  }

  return result;
}
