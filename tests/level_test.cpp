#include <log4cxx/level.h>
#include <log4cxx/logger.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

void dump(LoggerPtr logger)
{
	tcout << _T("Logger=") << logger->getName()
		<< _T("\tAssignedLevel=") << logger->getLevel().toString()
		<< _T("\tInheritedLevel=") << logger->getEffectiveLevel().toString()
		<< std::endl;
}

void setLevel(LoggerPtr logger, const Level& level)
{
	tcout << _T("Setting level ") << level.toString() << _T(" to logger ")
		<< logger->getName() << std::endl;

	logger->setLevel(level);
}

int main()
{
	int result = EXIT_SUCCESS;

	try
	{
		LoggerPtr root = Logger::getRootLogger();
		LoggerPtr X = Logger::getLogger(_T("X"));
		LoggerPtr XY = Logger::getLogger(_T("X.Y"));
		LoggerPtr XYZ = Logger::getLogger(_T("X.Y.Z"));

		setLevel(root, Level::getDebugLevel());
		dump(root); dump(X); dump(XY); dump(XYZ);
		tcout << std::endl;

		setLevel(root, Level::getDebugLevel());
		setLevel(X, Level::getInfoLevel());
		setLevel(XY, Level::getWarnLevel());
		setLevel(XYZ, Level::getErrorLevel());
		dump(root); dump(X); dump(XY); dump(XYZ);
		tcout << std::endl;

		setLevel(root, Level::getDebugLevel());
		setLevel(X, Level::getInfoLevel());
		setLevel(XY, Level::getOffLevel());
		setLevel(XYZ, Level::getErrorLevel());
		dump(root); dump(X); dump(XY); dump(XYZ);
		tcout << std::endl;

		setLevel(root, Level::getDebugLevel());
		setLevel(X, Level::getInfoLevel());
		setLevel(XY, Level::getOffLevel());
		setLevel(XYZ, Level::getOffLevel());
		dump(root); dump(X); dump(XY); dump(XYZ);
	}
	catch(Exception&)
	{
		result = EXIT_FAILURE;
	}

	return result;

}
