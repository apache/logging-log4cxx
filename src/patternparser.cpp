/***************************************************************************
                          patternparser.cpp  -  class PatternParser
                             -------------------
    begin                : mer avr 30 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#include <log4cxx/helpers/patternparser.h>
#include <log4cxx/helpers/dateformat.h>
#include <log4cxx/helpers/absolutetimedateformat.h>
#include <log4cxx/helpers/iso8601dateformat.h>
#include <log4cxx/helpers/datetimedateformat.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/level.h>
#include <log4cxx/mdc.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

#define ESCAPE_CHAR _T('%')

enum ParserState
{
	LITERAL_STATE,
	CONVERTER_STATE,
	MINUS_STATE,
	DOT_STATE,
	MIN_STATE,
	MAX_STATE,

	FULL_LOCATION_CONVERTER,
	//METHOD_LOCATION_CONVERTER = 1001;
	CLASS_LOCATION_CONVERTER,
	LINE_LOCATION_CONVERTER,
	FILE_LOCATION_CONVERTER,

	RELATIVE_TIME_CONVERTER,
	THREAD_CONVERTER,
	LEVEL_CONVERTER,
	NDC_CONVERTER,
	MESSAGE_CONVERTER,
};


PatternParser::PatternParser(const tstring& pattern)
: pattern(pattern), patternLength(pattern.length()), state(LITERAL_STATE), i(0)
{
}

void PatternParser::addToList(PatternConverterPtr& pc)
{
	if(head == 0)
	{
		head = tail = pc;
	} 
	else
	{
		tail->next = pc;
		tail = pc;
	}
}

tstring PatternParser::extractOption()
{
	if((i < patternLength) && (pattern.at(i) == _T('{')))
	{
		int end = pattern.find(_T('}'), i);
		if (end > i)
		{
			tstring r = pattern.substr(i + 1, end - (i + 1));
			i = end+1;
			return r;
		}
	}

	return tstring();
}

int PatternParser::extractPrecisionOption()
{
	tstring opt = extractOption();
	int r = 0;
	if(!opt.empty())
	{
		r = (int)ttol(opt.c_str());
		if(r <= 0)
		{
			LogLog::error(
				_T("Precision option (") + opt + _T(") isn't a positive integer."));
			r = 0;
		}
	}
	return r;
}

PatternConverterPtr PatternParser::parse()
{
	char c;
	i = 0;
	while(i < patternLength)
	{
		c = pattern.at(i++);
		switch(state)
		{
		case LITERAL_STATE:
			// In literal state, the last char is always a literal.
			if(i == patternLength)
			{
				currentLiteral << c;
				continue;
			}
			if(c == ESCAPE_CHAR)
			{
				// peek at the next char.
				switch(pattern.at(i))
				{
				case ESCAPE_CHAR:
					currentLiteral << c;
					i++; // move pointer
					break;
				case _T('n'):
					currentLiteral << std::endl;
					i++; // move pointer
					break;
				default:
					// test if currentLiteral is not empty
					if(currentLiteral.tellp() > std::streamoff(0))
					{
						PatternConverterPtr patternConverter(new LiteralPatternConverter(
							currentLiteral.str()));
						addToList(patternConverter);
						//LogLog.debug("Parsed LITERAL converter: \""
						//           +currentLiteral+"\".");
					}
					currentLiteral.str(_T(""));
					currentLiteral << c; // append %
					state = CONVERTER_STATE;
					formattingInfo.reset();
				}
			}
			else
			{
				currentLiteral << c;
			}
			break;
		case CONVERTER_STATE:
			currentLiteral << c;
			switch(c)
			{
			case _T('-'):
				formattingInfo.leftAlign = true;
				break;
			case _T('.'):
				state = DOT_STATE;
				break;
			default:
				if(c >= _T('0') && c <= _T('9'))
				{
					formattingInfo.min = c - _T('0');
					state = MIN_STATE;
				}
				else
					finalizeConverter(c);
			} // switch
			break;
			case MIN_STATE:
				currentLiteral << c;
				if(c >= _T('0') && c <= _T('9'))
					formattingInfo.min = formattingInfo.min*10 + (c - _T('0'));
				else if(c == _T('.'))
					state = DOT_STATE;
				else
				{
					finalizeConverter(c);
				}
				break;
			case DOT_STATE:
				currentLiteral << c;
				if(c >= _T('0') && c <= _T('9'))
				{
					formattingInfo.max = c - _T('0');
					state = MAX_STATE;
				}
				else {
					LOGLOG_ERROR(_T("Error occured in position ") << i
						<< _T(".\n Was expecting digit, instead got char \"") << c << _T("\"."));
					state = LITERAL_STATE;
				}
				break;
			case MAX_STATE:
				currentLiteral << c;
				if(c >= _T('0') && c <= _T('9'))
					formattingInfo.max = formattingInfo.max*10 + (c - _T('0'));
				else
				{
					finalizeConverter(c);
					state = LITERAL_STATE;
				}
				break;
		} // switch
	} // while
	// test if currentLiteral is not empty
	if(currentLiteral.tellp() > std::streamoff(0))
	{
		PatternConverterPtr patternConverter(
			new LiteralPatternConverter(currentLiteral.str()));
		addToList(patternConverter);
		//LogLog.debug("Parsed LITERAL converter: \""+currentLiteral+"\".");
	}
	return head;
}

void PatternParser::finalizeConverter(TCHAR c)
{
	PatternConverterPtr pc;

	switch(c)
	{
	case _T('c'):
		pc = new CategoryPatternConverter(formattingInfo,
			extractPrecisionOption());
		//LogLog::debug(_T("CATEGORY converter."));
		//formattingInfo.dump();
		currentLiteral.str(_T(""));
		break;
	case _T('d'):
	{
		tstring dateFormatStr;
		DateFormat * df = 0;
		tstring dOpt = extractOption();
		if(!dOpt.empty())
		{
			dateFormatStr = dOpt;
		}
		else
		{
			dateFormatStr = AbsoluteTimeDateFormat::ISO8601_DATE_FORMAT;
		}
		
		if(StringHelper::equalsIgnoreCase(dateFormatStr,
			AbsoluteTimeDateFormat::ISO8601_DATE_FORMAT))
			df = new ISO8601DateFormat();
		else if(StringHelper::equalsIgnoreCase(dateFormatStr,
			AbsoluteTimeDateFormat::ABS_TIME_DATE_FORMAT))
			df = new AbsoluteTimeDateFormat();
		else if(StringHelper::equalsIgnoreCase(dateFormatStr,
			AbsoluteTimeDateFormat::DATE_AND_TIME_DATE_FORMAT))
			df = new DateTimeDateFormat();
		else
		{
			df = new DateFormat(dateFormatStr);
		}
		pc = new DatePatternConverter(formattingInfo, df);
		//LogLog.debug("DATE converter {"+dateFormatStr+"}.");
		//formattingInfo.dump();
		currentLiteral.str(_T(""));
		break;
	}
	case _T('F'):
		pc = new LocationPatternConverter(formattingInfo,
			FILE_LOCATION_CONVERTER);
		//LogLog.debug("File name converter.");
		//formattingInfo.dump();
		currentLiteral.str(_T(""));
		break;
	case _T('l'):
		pc = new LocationPatternConverter(formattingInfo,
			FULL_LOCATION_CONVERTER);
		//LogLog.debug("Location converter.");
		//formattingInfo.dump();
		currentLiteral.str(_T(""));
		break;
	case _T('L'):

		pc = new LocationPatternConverter(formattingInfo,
			LINE_LOCATION_CONVERTER);
		//LogLog.debug("LINE NUMBER converter.");
		//formattingInfo.dump();
		currentLiteral.str(_T(""));
		break;
	case _T('m'):
		pc = new BasicPatternConverter(formattingInfo, MESSAGE_CONVERTER);
		//LogLog.debug("MESSAGE converter.");
		//formattingInfo.dump();
		currentLiteral.str(_T(""));
		break;
	case _T('p'):
		{
		pc = new BasicPatternConverter(formattingInfo, LEVEL_CONVERTER);
		//LogLog.debug("LEVEL converter.");
		//formattingInfo.dump();
		currentLiteral.str(_T(""));
		}
		break;
	case _T('r'):
		pc = new BasicPatternConverter(formattingInfo,
			RELATIVE_TIME_CONVERTER);
		//LogLog.debug("RELATIVE time converter.");
		//formattingInfo.dump();
		currentLiteral.str(_T(""));
		break;
	case _T('t'):
		pc = new BasicPatternConverter(formattingInfo, THREAD_CONVERTER);
		//LogLog.debug("THREAD converter.");
		//formattingInfo.dump();
		currentLiteral.str(_T(""));
		break;
		/*case 'u':
		if(i < patternLength) {
		char cNext = pattern.charAt(i);
		if(cNext >= '0' && cNext <= '9') {
		pc = new UserFieldPatternConverter(formattingInfo, cNext - '0');
		LogLog.debug("USER converter ["+cNext+"].");
		formattingInfo.dump();
		currentLiteral.setLength(0);
		i++;
		}
		else
		LogLog.error("Unexpected char" +cNext+" at position "+i);
		}
		break;*/
	case _T('x'):
		pc = new BasicPatternConverter(formattingInfo, NDC_CONVERTER);
		//LogLog.debug("NDC converter.");
		currentLiteral.str(_T(""));
		break;
	case _T('X'):
	{
		tstring xOpt = extractOption();
		pc = new MDCPatternConverter(formattingInfo, xOpt);
		currentLiteral.str(_T(""));
		break;
	}
	default:
		LOGLOG_ERROR(_T("Unexpected char [") << c << _T("] at position ") << i
			<<_T(" in conversion patterrn."));
		pc = new LiteralPatternConverter(currentLiteral.str());
		currentLiteral.str(_T(""));
	}

	addConverter(pc);
}

void PatternParser::addConverter(PatternConverterPtr& pc)
{
	currentLiteral.str(_T(""));
	// Add the pattern converter to the list.
	addToList(pc);
	// Next pattern is assumed to be a literal.
	state = LITERAL_STATE;
	// Reset formatting info
	formattingInfo.reset();
}

// ---------------------------------------------------------------------
//                      PatternConverters
// ---------------------------------------------------------------------
PatternParser::BasicPatternConverter::BasicPatternConverter(const FormattingInfo& formattingInfo, int type)
: PatternConverter(formattingInfo), type(type)
{
}

void PatternParser::BasicPatternConverter::convert(tostream& sbuf, const spi::LoggingEvent& event)
{
	switch(type)
	{
	case RELATIVE_TIME_CONVERTER:
		sbuf << (event.getTimeStamp() - LoggingEvent::getStartTime());
		break;
	case THREAD_CONVERTER:
		sbuf << event.getThreadId();
		break;
	case LEVEL_CONVERTER:
		sbuf << event.getLevel().toString();
		break;
	case NDC_CONVERTER:
		sbuf << event.getNDC();
		break;
	case MESSAGE_CONVERTER:
		sbuf << event.getRenderedMessage();
		break;
	}
}

PatternParser::LiteralPatternConverter::LiteralPatternConverter(const tstring& value)
: literal(value)
{
}

void PatternParser::LiteralPatternConverter::format(tostringstream& sbuf, const spi::LoggingEvent& e) 
{
	sbuf << literal;
}

void PatternParser::LiteralPatternConverter::convert(tostream& sbuf, const spi::LoggingEvent& event)
{
	sbuf << literal;
}

PatternParser::DatePatternConverter::DatePatternConverter(const FormattingInfo& formattingInfo, DateFormat * df)
: PatternConverter(formattingInfo), df(df)
{
}

PatternParser::DatePatternConverter::~DatePatternConverter()
{
	delete df;
}

void PatternParser::DatePatternConverter::convert(tostream& sbuf, const spi::LoggingEvent& event)
{
	df->format(sbuf, event.getTimeStamp());
}

PatternParser::MDCPatternConverter::MDCPatternConverter(const FormattingInfo& formattingInfo, const tstring& key)
: PatternConverter(formattingInfo), key(key)
{
}

void PatternParser::MDCPatternConverter::convert(tostream& sbuf, const spi::LoggingEvent& event)
{
	/**
	* if there is no additional options, we output every single
	* Key/Value pair for the MDC in a similar format to Hashtable.toString()
	*/

	if (key.empty())
	{
		sbuf << _T("{");
		std::set<tstring> keySet = event.getMDCKeySet();
		std::set<tstring>::iterator i;
		for (i = keySet.begin(); i != keySet.end(); i++)
		{
			tstring item = *i;
			tstring val = event.getMDC(item);
			sbuf << _T("{") << item << _T(",") << val << _T("}");
		}
		sbuf << _T("}");
	}
	else
	{
		/**
		* otherwise they just want a single key output
		*/
		sbuf << event.getMDC(key);
	}
}


PatternParser::LocationPatternConverter::LocationPatternConverter(const FormattingInfo& formattingInfo, int type)
: PatternConverter(formattingInfo), type(type)
{
}

void PatternParser::LocationPatternConverter::convert(tostream& sbuf, const spi::LoggingEvent& event)
{
	switch(type)
	{
	case FULL_LOCATION_CONVERTER:
		if (event.getFile() != 0)
		{
			sbuf << event.getFile() << _T("(") << event.getLine() << _T(")");
		}
		break;
	case LINE_LOCATION_CONVERTER:
		sbuf << event.getLine();
		break;
	case FILE_LOCATION_CONVERTER:
		if (event.getFile() != 0)
		{
			USES_CONVERSION;
			sbuf << A2T(event.getFile());
		}
		break;
	}
}

PatternParser::CategoryPatternConverter::CategoryPatternConverter(const FormattingInfo& formattingInfo, int precision)
: PatternConverter(formattingInfo), precision(precision)
{
}

void PatternParser::CategoryPatternConverter::convert(tostream& sbuf, const spi::LoggingEvent& event)
{
	const tstring& n = event.getLoggerName();

	if(precision <= 0)
	{

		sbuf << n;
	}
	else 
	{
		tstring::size_type len = n.length();
		
		// We substract 1 from 'len' when assigning to 'end' to avoid out of
		// bounds exception in return r.substring(end+1, len). This can happen if
		// precision is 1 and the category name ends with a dot.
		tstring::size_type end = len -1 ;
		for(int i = precision; i > 0; i--) 
		{
			end = n.rfind(_T('.'), end-1);
			if(end == tstring::npos)
			{
				sbuf << n;
				return;
			}
		}
		sbuf << n.substr(end+1, len - (end+1));
	}
}



