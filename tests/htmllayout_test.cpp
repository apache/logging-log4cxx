#include <stdlib.h>
#include <log4cxx/logger.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/htmllayout.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

int main()
{
  int result = EXIT_SUCCESS;

  try
  {
    LayoutPtr layout = new HTMLLayout();

    AppenderPtr consoleAppender =
      new ConsoleAppender(layout, _T("System.out"));

    LoggerPtr rootLogger = Logger::getRootLogger();
    rootLogger->addAppender(consoleAppender);

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
