#include <log4cxx/ndc.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

int main()
{
	int ret = EXIT_SUCCESS;

	try
	{
		if (!NDC::get().empty())
		{
			tcout << _T("1. empty NDC, get=") << NDC::get()
				<< _T(" (should be empty)") << std::endl;
			ret = EXIT_FAILURE;
		}

		NDC::push(_T("context1"));
		if (NDC::get()!= _T("context1"))
		{
			tcout << _T("2. push context1, get=") << NDC::get()
				<< _T(" (should be 'context1')") << std::endl;
			ret = EXIT_FAILURE;
		}

		NDC::push(_T("context2"));
		if (NDC::get()!= _T("context1 context2"))
		{
			tcout << _T("3. push context2, get=") << NDC::get()
				<< _T(" (should be 'context1 context2')") << std::endl;
			ret = EXIT_FAILURE;
		}

		NDC::push(_T("context3"));
		if (NDC::get()!= _T("context1 context2 context3"))
		{
			tcout << _T("4. push context3, get=") << NDC::get()
				<< _T(" (should be 'context1 context2 context3')") << std::endl;
			ret = EXIT_FAILURE;
		}

		if (NDC::getDepth() != 3)
		{
			tcout << _T("5. get depth=") << NDC::getDepth()
				<< _T(" (should be 3)") << std::endl;
			ret = EXIT_FAILURE;
		}

		String result = NDC::pop();
		if (result != _T("context3"))
		{
			tcout << _T("6. pop=") << result
				<< _T(" (should be 'context3')") << std::endl;
			ret = EXIT_FAILURE;
		}

		NDC::clear();
		if (!NDC::get().empty())
		{
			tcout << _T("7. clear, get=") << NDC::get()
				<< _T(" (should be empty)") << std::endl;
			ret = EXIT_FAILURE;
		}
	}
	catch(Exception&)
	{
		ret = EXIT_FAILURE;
	}

	return ret;
}
