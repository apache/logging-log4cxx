#include <log4cxx/spi/filter.h>
#include <log4cxx/logger.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/varia/stringmatchfilter.h>
#include <log4cxx/varia/levelmatchfilter.h>
#include <log4cxx/varia/levelrangefilter.h>
#include <log4cxx/varia/denyallfilter.h>
#include <log4cxx/spi/loggingevent.h>

using namespace log4cxx;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;
using namespace log4cxx::varia;

tostream& operator << (tostream& os, const Filter::FilterDecision& decision)
{
	switch (decision)
	{
	case Filter::DENY:
		os << _T("DENY");
		break;
	case Filter::NEUTRAL:
		os << _T("NEUTRAL");
		break;
	case Filter::ACCEPT:
		os << _T("ACCEPT");
		break;
	default:
		os << _T("UNKNOWN");
	}

	return os;
}

int main()
{
	int result = EXIT_SUCCESS;

	try
	{
		LoggerPtr root = Logger::getRootLogger();
		tstring fqcn = Logger::getStaticClass().getName();
		Filter::FilterDecision decision;

		// StringMatchFilterPtr
		StringMatchFilterPtr stringMatchFilter = new StringMatchFilter();
		stringMatchFilter->setStringToMatch(_T("es"));
		stringMatchFilter->setAcceptOnMatch(true);
		decision = stringMatchFilter->decide(
			LoggingEvent(fqcn, root, Level::getInfoLevel(), _T("test")));
		if (decision != Filter::ACCEPT)
		{
			tcout << _T("decision (should be ACCEPT): ") << decision << std::endl;
			return EXIT_FAILURE;
		}

		stringMatchFilter->setAcceptOnMatch(false);
		decision = stringMatchFilter->decide(
			LoggingEvent(fqcn, root, Level::getInfoLevel(), _T("test")));
		if (decision != Filter::DENY)
		{
			tcout << _T("decision (should be DENY): ") << decision << std::endl;
			return EXIT_FAILURE;
		}

		stringMatchFilter->setStringToMatch(_T("se"));
		decision = stringMatchFilter->decide(
			LoggingEvent(fqcn, root, Level::getInfoLevel(), _T("test")));
		if (decision != Filter::NEUTRAL)
		{
			tcout << _T("decision (should be NEUTRAL): ") << decision << std::endl;
			return EXIT_FAILURE;
		}

		// LevelMatchFilter
		LevelMatchFilterPtr levelMatchFilter = new LevelMatchFilter();
		levelMatchFilter->setLevelToMatch(_T("INFO"));
		levelMatchFilter->setAcceptOnMatch(true);
		decision = levelMatchFilter->decide(
			LoggingEvent(fqcn, root, Level::getInfoLevel(), _T("test")));
		if (decision != Filter::ACCEPT)
		{
			tcout << _T("decision (should be ACCEPT): ") << decision << std::endl;
			return EXIT_FAILURE;
		}

		levelMatchFilter->setAcceptOnMatch(false);
		decision = levelMatchFilter->decide(
			LoggingEvent(fqcn, root, Level::getInfoLevel(), _T("test")));
		if (decision != Filter::DENY)
		{
			tcout << _T("decision (should be DENY): ") << decision << std::endl;
			return EXIT_FAILURE;
		}

		levelMatchFilter->setLevelToMatch(_T("DEBUG"));
		decision = levelMatchFilter->decide(
			LoggingEvent(fqcn, root, Level::getInfoLevel(), _T("test")));
		if (decision != Filter::NEUTRAL)
		{
			tcout << _T("decision (should be NEUTRAL): ") << decision << std::endl;
			return EXIT_FAILURE;
		}

		// LevelRangeFilter
		LevelRangeFilterPtr levelRangeFilter = new LevelRangeFilter();
		levelRangeFilter->setLevelMin(Level::getDebugLevel());
		levelRangeFilter->setLevelMax(Level::getWarnLevel());
		levelRangeFilter->setAcceptOnMatch(true);
		decision = levelRangeFilter->decide(
			LoggingEvent(fqcn, root, Level::getInfoLevel(), _T("test")));
		if (decision != Filter::ACCEPT)
		{
			tcout << _T("decision (should be ACCEPT): ") << decision << std::endl;
			return EXIT_FAILURE;
		}

		levelRangeFilter->setAcceptOnMatch(false);
		decision = levelRangeFilter->decide(
			LoggingEvent(fqcn, root, Level::getInfoLevel(), _T("test")));
		if (decision != Filter::NEUTRAL)
		{
			tcout << _T("decision (should be NEUTRAL): ") << decision << std::endl;
			return EXIT_FAILURE;
		}

		decision = levelRangeFilter->decide(
			LoggingEvent(fqcn, root, Level::getErrorLevel(), _T("test")));
		if (decision != Filter::DENY)
		{
			tcout << _T("decision (should be DENY): ") << decision << std::endl;
			return EXIT_FAILURE;
		}

		// DenyAllFilter

		DenyAllFilterPtr denyAllFilter = new DenyAllFilter();
		decision = denyAllFilter->decide(
			LoggingEvent(fqcn, root, Level::getInfoLevel(), _T("test")));
		if (decision != Filter::DENY)
		{
			tcout << _T("decision (should be DENY): ") << decision << std::endl;
			return EXIT_FAILURE;
		}
	}
	catch(Exception&)
	{
		result = EXIT_FAILURE;
	}

	return result;
}
