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
		tcout << "logger=" << logger->getName()
			<< ", parent=" << logger->getParent()->getName() << std::endl;

		logger = Logger::getLogger(_T("X"));
		tcout << "logger=" << logger->getName()
			<< ", parent=" << logger->getParent()->getName() << std::endl;

		logger = Logger::getLogger(_T("X.Y.Z"));
		tcout << "logger=" << logger->getName()
			<< ", parent=" << logger->getParent()->getName() << std::endl;

		logger = Logger::getLogger(_T("X.Y"));
		tcout << "logger=" << logger->getName()
			<< ", parent=" << logger->getParent()->getName() << std::endl;

		logger = Logger::getLogger(_T("X.Y.Z"));
		tcout << "logger=" << logger->getName()
			<< ", parent=" << logger->getParent()->getName() << std::endl;
	}
	catch(Exception&)
	{
		result = EXIT_FAILURE;
	}

	return result;

}
