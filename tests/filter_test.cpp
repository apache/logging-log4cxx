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

		// StringMatchFilterPtr
		StringMatchFilterPtr stringMatchFilter = new StringMatchFilter();
		stringMatchFilter->setStringToMatch(_T("es"));
		stringMatchFilter->setAcceptOnMatch(true);
		tcout << _T("decision (should be ACCEPT): ")
			<< (Filter::FilterDecision)stringMatchFilter->decide(
				LoggingEvent(root, Level::INFO, _T("test")))
			<< std::endl;
		stringMatchFilter->setAcceptOnMatch(false);
		tcout << _T("decision (should be DENY): ")
			<< (Filter::FilterDecision)stringMatchFilter->decide(
				LoggingEvent(root, Level::INFO, _T("test")))
			<< std::endl;
		stringMatchFilter->setStringToMatch(_T("se"));
		tcout << _T("decision (should be NEUTRAL): ")
			<< (Filter::FilterDecision)stringMatchFilter->decide(
				LoggingEvent(root, Level::INFO, _T("test")))
			<< std::endl;

		// LevelMatchFilter
		LevelMatchFilterPtr levelMatchFilter = new LevelMatchFilter();
		levelMatchFilter->setLevelToMatch(_T("INFO"));
		levelMatchFilter->setAcceptOnMatch(true);
		tcout << _T("decision (should be ACCEPT): ")
			<< (Filter::FilterDecision)levelMatchFilter->decide(
				LoggingEvent(root, Level::INFO, _T("test")))
			<< std::endl;
		levelMatchFilter->setAcceptOnMatch(false);
		tcout << _T("decision (should be DENY): ")
			<< (Filter::FilterDecision)levelMatchFilter->decide(
				LoggingEvent(root, Level::INFO, _T("test")))
			<< std::endl;
		levelMatchFilter->setLevelToMatch(_T("DEBUG"));
		tcout << _T("decision (should be NEUTRAL): ")
			<< (Filter::FilterDecision)levelMatchFilter->decide(
				LoggingEvent(root, Level::INFO, _T("test")))
			<< std::endl;

		// LevelRangeFilter
		LevelRangeFilterPtr levelRangeFilter = new LevelRangeFilter();
		levelRangeFilter->setLevelMin(Level::DEBUG);
		levelRangeFilter->setLevelMax(Level::WARN);
		levelRangeFilter->setAcceptOnMatch(true);
		tcout << _T("decision (should be ACCEPT): ")
			<< (Filter::FilterDecision)levelRangeFilter->decide(
				LoggingEvent(root, Level::INFO, _T("test")))
			<< std::endl;
		levelRangeFilter->setAcceptOnMatch(false);
		tcout << _T("decision (should be NEUTRAL): ")
			<< (Filter::FilterDecision)levelRangeFilter->decide(
				LoggingEvent(root, Level::INFO, _T("test")))
			<< std::endl;
		tcout << _T("decision (should be DENY): ")
			<< (Filter::FilterDecision)levelRangeFilter->decide(
				LoggingEvent(root, Level::ERROR, _T("test")))
			<< std::endl;

		// DenyAllFilter
		DenyAllFilterPtr denyAllFilter = new DenyAllFilter();
		tcout << _T("decision (should be DENY): ")
			<< (Filter::FilterDecision)denyAllFilter->decide(
				LoggingEvent(root, Level::INFO, _T("test")))
			<< std::endl;
	}
	catch(Exception&)
	{
		result = EXIT_FAILURE;
	}

	return result;

}
