#include <log4cxx/mdc.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

int main()
{
	int ret = EXIT_SUCCESS;

	try
	{
		if (!MDC::get(_T("key1")).empty())
		{
			tcout << _T("1. empty MDC key1, get=") << MDC::get(_T("key1")) << std::endl;
			ret = EXIT_FAILURE;
		}

		MDC::put(_T("key1"), _T("context1"));
		if (MDC::get(_T("key1")) != _T("context1"))
		{
			tcout << _T("2. put key1=context1, get key1=") 
				<< MDC::get(_T("key1")) << std::endl;
			ret = EXIT_FAILURE;
		}

		MDC::put(_T("key2"), _T("context2"));
		if (MDC::get(_T("key2")) != _T("context2"))
		{
			tcout << _T("3. put key2=context2, get key2=") 
				<< MDC::get(_T("key2")) << std::endl;
			ret = EXIT_FAILURE;
		}

		String result = MDC::remove(_T("key2"));
		if (result != _T("context2") && !MDC::get(_T("key2")).empty())
		{
			tcout << _T("4. remove key2: result=") << result
				<< _T(", get key2=") << MDC::get(_T("key2")) << std::endl;
			ret = EXIT_FAILURE;
		}

		MDC::clear();
		if (!MDC::get(_T("key1")).empty())
		{
			tcout << _T("5. clear: get key1=") << MDC::get(_T("key1")) << std::endl;
			ret = EXIT_FAILURE;
		}
	}
	catch(Exception&)
	{
		ret = EXIT_FAILURE;
	}

	return ret;
}
