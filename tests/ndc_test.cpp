#include <log4cxx/ndc.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

int main()
{
	int result = EXIT_SUCCESS;

	try
	{
		tcout << _T("1. empty NDC: ") << NDC::get() << std::endl;
		NDC::push(_T("context1"));
		tcout << _T("2. push context1: ") << NDC::get() << std::endl;
		NDC::push(_T("context2"));
		tcout << _T("3. push context2: ") << NDC::get() << std::endl;
		NDC::push(_T("context3"));
		tcout << _T("4. push context3: ") << NDC::get() << std::endl;
		tcout << _T("5. get depth: ") << NDC::getDepth() << std::endl;
		tcout << _T("6. pop: ") << NDC::pop() << std::endl;
		NDC::clear();
		tcout << _T("7. clear: ") << NDC::get() << std::endl;
	}
	catch(Exception&)
	{
		result = EXIT_FAILURE;
	}

	return result;
}
