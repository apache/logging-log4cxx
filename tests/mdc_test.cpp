#include <log4cxx/mdc.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

int main()
{
	int result = EXIT_SUCCESS;

	try
	{
		tcout << _T("1. empty MDC key1: ") << MDC::get(_T("key1")) << std::endl;
		MDC::put(_T("key1"), _T("context1"));
		tcout << _T("2. put key1: ") << MDC::get(_T("key1")) << std::endl;
		MDC::put(_T("key2"), _T("context2"));
		tcout << _T("3. put key2: ") << MDC::get(_T("key2")) << std::endl;
		tcout << _T("4. remove key2: ") << MDC::remove(_T("key2")) << std::endl;
		tcout << _T("5. empty MDC key2: ") << MDC::get(_T("key2")) << std::endl;
		MDC::clear();
		tcout << _T("6. clear") << std::endl;
		tcout << _T("7. empty MDC key1: ") << MDC::get(_T("key1")) << std::endl;
	}
	catch(Exception&)
	{
		result = EXIT_FAILURE;
	}

	return result;
}
