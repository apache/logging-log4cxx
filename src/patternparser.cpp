/*
 * Copyright 2003-2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <log4cxx/helpers/patternparser.h>
#include <log4cxx/helpers/absolutetimedateformat.h>
#include <log4cxx/helpers/iso8601dateformat.h>
#include <log4cxx/helpers/strftimedateformat.h>
#include <log4cxx/helpers/datetimedateformat.h>
#include <log4cxx/helpers/cacheddateformat.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/level.h>
#include <log4cxx/mdc.h>
#include <log4cxx/helpers/transcoder.h>

#include <apr_pools.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;
using namespace log4cxx::spi::location;

#define ESCAPE_CHAR LOG4CXX_STR('%')

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
        MESSAGE_CONVERTER
};


PatternParser::PatternParser(const LogString& pattern, const LogString& timeZone)
:
   state(LITERAL_STATE),
   currentLiteral(),
   patternLength(pattern.length()),
   i(0),
   head(),
   tail(),
   formattingInfo(),
   pattern(pattern),
   timeZone(timeZone)
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

LogString PatternParser::extractOption()
{
        if((i < patternLength) && (pattern.at(i) == LOG4CXX_STR('{')))
        {
                size_t end = pattern.find(LOG4CXX_STR('}'), i);
                if (end > i)
                {
                        LogString r = pattern.substr(i + 1, end - (i + 1));
                        i = end+1;
                        return r;
                }
        }

        return LogString();
}

int PatternParser::extractPrecisionOption()
{
        LogString opt = extractOption();
        int r = 0;
        if(!opt.empty())
        {
                r = StringHelper::toInt(opt);
                if(r <= 0)
                {
                        LogLog::error(
                                ((LogString) LOG4CXX_STR("Precision option ("))
                                 + opt + LOG4CXX_STR(") isn't a positive integer."));
                        r = 0;
                }
        }
        return r;
}

PatternConverterPtr PatternParser::parse()
{
        logchar c;
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
                                currentLiteral.append(1, c);
                                continue;
                        }
                        if(c == ESCAPE_CHAR)
                        {
                                // peek at the next char.
                                switch(pattern.at(i))
                                {
                                case ESCAPE_CHAR:
                                        currentLiteral.append(1, c);
                                        i++; // move pointer
                                        break;
                                case LOG4CXX_STR('n'):
#if defined(_WIN32)
                                        currentLiteral.append(LOG4CXX_STR("\x0D\x0A"));
#else
                                        currentLiteral.append(1, LOG4CXX_STR('\x0A'));
#endif
                                        i++; // move pointer
                                        break;
                                default:
                                        // test if currentLiteral is not empty
                                        if(!currentLiteral.empty())
                                        {
                                                PatternConverterPtr patternConverter(new LiteralPatternConverter(
                                                        currentLiteral));
                                                addToList(patternConverter);
                                                //LogLog.debug("Parsed LITERAL converter: \""
                                                //           +currentLiteral+"\".");
                                        }
                                        currentLiteral.erase(currentLiteral.begin(), currentLiteral.end());
                                        currentLiteral.append(1, c); // append %
                                        state = CONVERTER_STATE;
                                        formattingInfo.reset();
                                }
                        }
                        else
                        {
                                currentLiteral.append(1, c);
                        }
                        break;
                case CONVERTER_STATE:
                        currentLiteral.append(1, c);
                        switch(c)
                        {
                        case LOG4CXX_STR('-'):
                                formattingInfo.leftAlign = true;
                                break;
                        case LOG4CXX_STR('.'):
                                state = DOT_STATE;
                                break;
                        default:
                                if(c >= LOG4CXX_STR('0') && c <= LOG4CXX_STR('9'))
                                {
                                        formattingInfo.minChar = c - LOG4CXX_STR('0');
                                        state = MIN_STATE;
                                }
                                else
                                        finalizeConverter(c);
                        } // switch
                        break;
                        case MIN_STATE:
                                currentLiteral.append(1, c);
                                if(c >= LOG4CXX_STR('0') && c <= LOG4CXX_STR('9'))
                                        formattingInfo.minChar = formattingInfo.minChar*10 + (c - LOG4CXX_STR('0'));
                                else if(c == LOG4CXX_STR('.'))
                                        state = DOT_STATE;
                                else
                                {
                                        finalizeConverter(c);
                                }
                                break;
                        case DOT_STATE:
                                currentLiteral.append(1, c);
                                if(c >= LOG4CXX_STR('0') && c <= LOG4CXX_STR('9'))
                                {
                                        formattingInfo.maxChar = c - LOG4CXX_STR('0');
                                        state = MAX_STATE;
                                }
                                else {
                                        Pool p;
                                        LogLog::error(((LogString) LOG4CXX_STR("Error occured in position "))
                                                + StringHelper::toString(i, p)
                                                + LOG4CXX_STR(".\n Was expecting digit, instead got char \"")
                                                + LogString(1, c)
                                                + LOG4CXX_STR("\"."));
                                        state = LITERAL_STATE;
                                }
                                break;
                        case MAX_STATE:
                                currentLiteral.append(1, c);
                                if(c >= LOG4CXX_STR('0') && c <= LOG4CXX_STR('9'))
                                        formattingInfo.maxChar = formattingInfo.maxChar*10 + (c - LOG4CXX_STR('0'));
                                else
                                {
                                        finalizeConverter(c);
                                        state = LITERAL_STATE;
                                }
                                break;
                } // switch
        } // while
        // test if currentLiteral is not empty
        if(!currentLiteral.empty())
        {
                PatternConverterPtr patternConverter(
                        new LiteralPatternConverter(currentLiteral));
                addToList(patternConverter);
                //LogLog.debug("Parsed LITERAL converter: \""+currentLiteral+"\".");
        }
        return head;
}

void PatternParser::finalizeConverter(logchar c)
{
        PatternConverterPtr pc;

        switch(c)
        {
        case LOG4CXX_STR('c'):
                pc = new CategoryPatternConverter(formattingInfo,
                        extractPrecisionOption());
                //LogLog::debug(LOG4CXX_STR("CATEGORY converter."));
                //formattingInfo.dump();
                currentLiteral.erase(currentLiteral.begin(), currentLiteral.end());
                break;
        case LOG4CXX_STR('d'):
        {
                DateFormat * df = 0;
                LogString dateFormatStr(extractOption());
                if(dateFormatStr.empty() ||
                        StringHelper::equalsIgnoreCase(dateFormatStr,
                        LOG4CXX_STR("ISO8601"), LOG4CXX_STR("iso8601")))
                        df = new ISO8601DateFormat();
                else if(StringHelper::equalsIgnoreCase(dateFormatStr,
                        LOG4CXX_STR("ABSOLUTE"), LOG4CXX_STR("absolute")))
                        df = new AbsoluteTimeDateFormat();
                else if(StringHelper::equalsIgnoreCase(dateFormatStr,
                        LOG4CXX_STR("DATE"), LOG4CXX_STR("date")))
                        df = new DateTimeDateFormat();
                else
                {
                        if (dateFormatStr.find(LOG4CXX_STR('%')) == std::string::npos) {
                            df = new SimpleDateFormat(dateFormatStr);
                        } else {
                                df = new StrftimeDateFormat(dateFormatStr);
                        }
                }
                DateFormatPtr formatter(df);
                df = new CachedDateFormat(formatter);
                pc = new DatePatternConverter(formattingInfo, df);
                //LogLog.debug("DATE converter {"+dateFormatStr+"}.");
                //formattingInfo.dump();
                currentLiteral.erase(currentLiteral.begin(), currentLiteral.end());
                break;
        }
        case LOG4CXX_STR('F'):
                pc = new LocationPatternConverter(formattingInfo,
                        FILE_LOCATION_CONVERTER);
                //LogLog.debug("File name converter.");
                //formattingInfo.dump();
                currentLiteral.erase(currentLiteral.begin(), currentLiteral.end());
                break;
        case LOG4CXX_STR('l'):
                pc = new LocationPatternConverter(formattingInfo,
                        FULL_LOCATION_CONVERTER);
                //LogLog.debug("Location converter.");
                //formattingInfo.dump();
                currentLiteral.erase(currentLiteral.begin(), currentLiteral.end());
                break;
        case LOG4CXX_STR('L'):

                pc = new LocationPatternConverter(formattingInfo,
                        LINE_LOCATION_CONVERTER);
                //LogLog.debug("LINE NUMBER converter.");
                //formattingInfo.dump();
                currentLiteral.erase(currentLiteral.begin(), currentLiteral.end());
                break;
        case LOG4CXX_STR('m'):
                pc = new BasicPatternConverter(formattingInfo, MESSAGE_CONVERTER);
                //LogLog.debug("MESSAGE converter.");
                //formattingInfo.dump();
                currentLiteral.erase(currentLiteral.begin(), currentLiteral.end());
                break;
        case LOG4CXX_STR('p'):
                {
                pc = new BasicPatternConverter(formattingInfo, LEVEL_CONVERTER);
                //LogLog.debug("LEVEL converter.");
                //formattingInfo.dump();
        currentLiteral.erase(currentLiteral.begin(), currentLiteral.end());
                }
                break;
        case LOG4CXX_STR('r'):
                pc = new BasicPatternConverter(formattingInfo,
                        RELATIVE_TIME_CONVERTER);
                //LogLog.debug("RELATIVE time converter.");
                //formattingInfo.dump();
                currentLiteral.erase(currentLiteral.begin(), currentLiteral.end());
                break;

        case LOG4CXX_STR('t'):
                pc = new BasicPatternConverter(formattingInfo, THREAD_CONVERTER);
                //LogLog.debug("THREAD converter.");
                //formattingInfo.dump();
        currentLiteral.erase(currentLiteral.begin(), currentLiteral.end());
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

        case LOG4CXX_STR('x'):
                pc = new BasicPatternConverter(formattingInfo, NDC_CONVERTER);
                //LogLog.debug("NDC converter.");
                currentLiteral.erase(currentLiteral.begin(), currentLiteral.end());
                break;

        case LOG4CXX_STR('X'):
        {
                LogString xOpt = extractOption();
                pc = new MDCPatternConverter(formattingInfo, xOpt);
                currentLiteral.erase(currentLiteral.begin(), currentLiteral.end());
                break;
        }

        default:
        {
                Pool p;
                LogLog::error(((LogString) LOG4CXX_STR("Unexpected char ["))
                        + LogString(1, c)
                        + LOG4CXX_STR("] at position ")
                        + StringHelper::toString(i, p)
                        + LOG4CXX_STR(" in conversion pattern."));
                pc = new LiteralPatternConverter(currentLiteral);
                currentLiteral.erase(currentLiteral.begin(), currentLiteral.end());
        }
        }

        addConverter(pc);
}

void PatternParser::addConverter(PatternConverterPtr& pc)
{
        currentLiteral.erase(currentLiteral.begin(), currentLiteral.end());
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

void PatternParser::BasicPatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event,
        Pool& pool) const
{
        switch(type)
        {
        case RELATIVE_TIME_CONVERTER:
                sbuf.append(
                  StringHelper::toString((event->getTimeStamp() - LoggingEvent::getStartTime())/1000, pool));
                break;
        case THREAD_CONVERTER:
                sbuf.append(event->getThreadName());
                break;
        case LEVEL_CONVERTER:
                sbuf.append(event->getLevel()->toString());
                break;
        case NDC_CONVERTER:
                sbuf.append(event->getNDC());
                break;
        case MESSAGE_CONVERTER:
                sbuf.append(event->getRenderedMessage());
                break;
        }
}

PatternParser::LiteralPatternConverter::LiteralPatternConverter(const LogString& value)
: literal(value)
{
}


void PatternParser::LiteralPatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event,
        Pool& pool) const
{
        sbuf.append(literal);
}

PatternParser::DatePatternConverter::DatePatternConverter(const FormattingInfo& formattingInfo, DateFormat * df)
: PatternConverter(formattingInfo), df(df)
{
}

PatternParser::DatePatternConverter::~DatePatternConverter()
{
        delete df;
}

void PatternParser::DatePatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event, Pool& p) const
{
        df->format(sbuf, event->getTimeStamp(), p);
}

PatternParser::MDCPatternConverter::MDCPatternConverter(const FormattingInfo& formattingInfo, const LogString& key)
: PatternConverter(formattingInfo), key(key)
{
}

void PatternParser::MDCPatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event,
        Pool& pool) const
{
        /**
        * if there is no additional options, we output every single
        * Key/Value pair for the MDC in a similar format to Hashtable.toString()
        */

        if (key.empty())
        {
                sbuf.append(1, LOG4CXX_STR('{'));
                std::set<LogString> keySet = event->getMDCKeySet();
                std::set<LogString>::iterator i;
                for (i = keySet.begin(); i != keySet.end(); i++)
                {
                        LogString item = *i;
                        LogString val = event->getMDC(item);
                        sbuf.append(1, LOG4CXX_STR('{'));
                        sbuf.append(item);
                        sbuf.append(1, LOG4CXX_STR(','));
                        sbuf.append(val);
                        sbuf.append(1, LOG4CXX_STR('}'));
                }
                sbuf.append(1, LOG4CXX_STR('}'));
        }
        else
        {
                /**
                * otherwise they just want a single key output
                */
                sbuf.append(event->getMDC(key));
        }
}


PatternParser::LocationPatternConverter::LocationPatternConverter(const FormattingInfo& formattingInfo, int type)
: PatternConverter(formattingInfo), type(type)
{
}

void PatternParser::LocationPatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event, Pool& pool) const
{
        const LocationInfo& locInfo = event->getLocationInformation();
        switch(type)
        {
        case FULL_LOCATION_CONVERTER:
                Transcoder::decode(locInfo.getFileName(), sbuf);
                sbuf.append(1, LOG4CXX_STR('('));
                sbuf.append(StringHelper::toString(locInfo.getLineNumber(), pool));
                sbuf.append(1, LOG4CXX_STR(')'));
                break;
        case LINE_LOCATION_CONVERTER:
                sbuf.append(StringHelper::toString(locInfo.getLineNumber(), pool));
                break;
        case FILE_LOCATION_CONVERTER:
                Transcoder::decode(locInfo.getFileName(), sbuf);
        }
}

PatternParser::CategoryPatternConverter::CategoryPatternConverter(const FormattingInfo&
        formattingInfo, int precision)
: PatternConverter(formattingInfo), precision(precision)
{
}

void PatternParser::CategoryPatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event,
        Pool& pool) const
{

        if(precision <= 0)
        {
                sbuf.append(event->getLoggerName());
        }
        else
        {
                const LogString& n = event->getLoggerName();
                LogString::size_type len = n.length();

                // We substract 1 from 'len' when assigning to 'end' to avoid out of
                // bounds exception in return r.substring(end+1, len). This can happen if
                // precision is 1 and the category name ends with a dot.
                LogString::size_type end = len -1 ;
                for(int i = precision; i > 0; i--)
                {
                        end = n.rfind(LOG4CXX_STR('.'), end-1);
                        if(end == LogString::npos)
                        {
                                sbuf.append(n);
                                return;
                        }
                }
                sbuf.append(n, end+1, len - (end+1));
        }
}



