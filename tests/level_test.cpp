#include <log4cxx/level.h>
#include <log4cxx/logger.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

class dump
{
public:
	dump(LoggerPtr logger) : logger(logger) {}
	LoggerPtr logger;
};

ostream& operator<<(ostream &os, const dump& dump)
{
	os << _T("Logger=") << dump.logger->getName()
		<< _T("\tAssignedLevel=") << dump.logger->getLevel().toString()
		<< _T("\tInheritedLevel=") << dump.logger->getEffectiveLevel().toString()
		<< std::endl;

	return os;
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

		root->setLevel(Level::getDebugLevel());
		if (root->getLevel() != Level::getDebugLevel()
			|| root->getEffectiveLevel() != Level::getDebugLevel()
			|| X->getLevel() != Level::getOffLevel()
			|| X->getEffectiveLevel() != Level::getDebugLevel()
			|| XY->getLevel() != Level::getOffLevel()
			|| XY->getEffectiveLevel() != Level::getDebugLevel()
			|| XYZ->getLevel() != Level::getOffLevel()
			|| XYZ->getEffectiveLevel() != Level::getDebugLevel())
		{
			tcout << dump(root) << dump(X) << dump(XY) << dump(XYZ) << std::endl;
			result = EXIT_FAILURE;
		}

		root->setLevel(Level::getDebugLevel());
		X->setLevel(Level::getInfoLevel());
		XY->setLevel(Level::getWarnLevel());
		XYZ->setLevel(Level::getErrorLevel());
		if (root->getLevel() != Level::getDebugLevel()
			|| root->getEffectiveLevel() != Level::getDebugLevel()
			|| X->getLevel() != Level::getInfoLevel()
			|| X->getEffectiveLevel() != Level::getInfoLevel()
			|| XY->getLevel() != Level::getWarnLevel()
			|| XY->getEffectiveLevel() != Level::getWarnLevel()
			|| XYZ->getLevel() != Level::getErrorLevel()
			|| XYZ->getEffectiveLevel() != Level::getErrorLevel())
		{
			tcout << dump(root) << dump(X) << dump(XY) << dump(XYZ) << std::endl;
			result = EXIT_FAILURE;
		}

		root->setLevel(Level::getDebugLevel());
		X->setLevel(Level::getInfoLevel());
		XY->setLevel(Level::getOffLevel());
		XYZ->setLevel(Level::getErrorLevel());
		if (root->getLevel() != Level::getDebugLevel()
			|| root->getEffectiveLevel() != Level::getDebugLevel()
			|| X->getLevel() != Level::getInfoLevel()
			|| X->getEffectiveLevel() != Level::getInfoLevel()
			|| XY->getLevel() != Level::getOffLevel()
			|| XY->getEffectiveLevel() != Level::getInfoLevel()
			|| XYZ->getLevel() != Level::getErrorLevel()
			|| XYZ->getEffectiveLevel() != Level::getErrorLevel())
		{
			tcout << dump(root) << dump(X) << dump(XY) << dump(XYZ) << std::endl;
			result = EXIT_FAILURE;
		}

		root->setLevel(Level::getDebugLevel());
		X->setLevel(Level::getInfoLevel());
		XY->setLevel(Level::getOffLevel());
		XYZ->setLevel(Level::getOffLevel());
		if (root->getLevel() != Level::getDebugLevel()
			|| root->getEffectiveLevel() != Level::getDebugLevel()
			|| X->getLevel() != Level::getInfoLevel()
			|| X->getEffectiveLevel() != Level::getInfoLevel()
			|| XY->getLevel() != Level::getOffLevel()
			|| XY->getEffectiveLevel() != Level::getInfoLevel()
			|| XYZ->getLevel() != Level::getOffLevel()
			|| XYZ->getEffectiveLevel() != Level::getInfoLevel())
		{
			tcout << dump(root) << dump(X) << dump(XY) << dump(XYZ);
			result = EXIT_FAILURE;
		}
	}
	catch(Exception&)
	{
		result = EXIT_FAILURE;
	}

	return result;

}
