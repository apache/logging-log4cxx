#include <log4cxx/logger.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

int main()
{
	int result = EXIT_SUCCESS;

	try
	{
		LoggerPtr logger;

		logger = Logger::getLogger(_T("X.Y.Z"));
		if (logger->getParent()->getName() != _T("root"))
		{
			tcout << "logger=" << logger->getName()
				<< ", parent=" << logger->getParent()->getName()
				<< _T(" (should be root)") << std::endl;
			result = EXIT_FAILURE;
		}

		logger = Logger::getLogger(_T("X"));
		if (logger->getParent()->getName() != _T("root"))
		{
			tcout << "logger=" << logger->getName()
				<< ", parent=" << logger->getParent()->getName()
				<< _T(" (should be root)") << std::endl;
			result = EXIT_FAILURE;
		}

		logger = Logger::getLogger(_T("X.Y.Z"));
		if (logger->getParent()->getName() != _T("X"))
		{
			tcout << "logger=" << logger->getName()
				<< ", parent=" << logger->getParent()->getName()
				<< _T(" (should be X)") << std::endl;
			result = EXIT_FAILURE;
		}

		logger = Logger::getLogger(_T("X.Y"));
		if (logger->getParent()->getName() != _T("X"))
		{
			tcout << "logger=" << logger->getName()
				<< ", parent=" << logger->getParent()->getName()
				<< _T(" (should be X)") << std::endl;
			result = EXIT_FAILURE;
		}

		logger = Logger::getLogger(_T("X.Y.Z"));
		if (logger->getParent()->getName() != _T("X.Y"))
		{
			tcout << "logger=" << logger->getName()
				<< ", parent=" << logger->getParent()->getName()
				<< _T(" (should be X.Y)") << std::endl;
			result = EXIT_FAILURE;
		}
	}
	catch(Exception&)
	{
		result = EXIT_FAILURE;
	}

	return result;

}
