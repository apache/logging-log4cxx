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
#include <sstream>
#include <log4cxx/helpers/exception.h>

#include <apr_pools.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;
using namespace log4cxx::pattern;

#define ESCAPE_CHAR LOG4CXX_STR('%')

#define ADD_PATTERN(specifier, classname) \
globalRulesRegistry.insert(InternalPatternConverterMap::value_type(LOG4CXX_STR(specifier), classname::newInstance))

const PatternParser::InternalPatternConverterMap& PatternParser::getGlobalRulesRegistry() {
  static InternalPatternConverterMap globalRulesRegistry;
  ADD_PATTERN("c", LoggerPatternConverter);
  ADD_PATTERN("logger", LoggerPatternConverter);

  ADD_PATTERN("C", ClassNamePatternConverter);
  ADD_PATTERN("class", ClassNamePatternConverter);

  ADD_PATTERN("d", DatePatternConverter);
  ADD_PATTERN("date", DatePatternConverter);

  ADD_PATTERN("F", FileLocationPatternConverter);
  ADD_PATTERN("file", FileLocationPatternConverter);

  ADD_PATTERN("l", FullLocationPatternConverter);

  ADD_PATTERN("L", LineLocationPatternConverter);
  ADD_PATTERN("line", LineLocationPatternConverter);

  ADD_PATTERN("m", MessagePatternConverter);
  ADD_PATTERN("message", MessagePatternConverter);

  ADD_PATTERN("n", LineSeparatorPatternConverter);

  ADD_PATTERN("M", MethodLocationPatternConverter);
  ADD_PATTERN("method", MethodLocationPatternConverter);

  ADD_PATTERN("p", LevelPatternConverter);
  ADD_PATTERN("level", LevelPatternConverter);

  ADD_PATTERN("r", RelativeTimePatternConverter);
  ADD_PATTERN("relative", RelativeTimePatternConverter);

  ADD_PATTERN("t", ThreadPatternConverter);
  ADD_PATTERN("thread", ThreadPatternConverter);

  ADD_PATTERN("x", NDCPatternConverter);
  ADD_PATTERN("ndc", NDCPatternConverter);

  ADD_PATTERN("X", PropertiesPatternConverter);
  ADD_PATTERN("properties", PropertiesPatternConverter);


  ADD_PATTERN("throwable", ThrowableInformationPatternConverter);

  return globalRulesRegistry;
}

void PatternParser::logError(const LogString& msg) {
  LogLog::error(msg);
}

void PatternParser::logWarn(const LogString& msg) {
  LogLog::warn(msg);
}


PatternParser::PatternParser(const LogString& pattern)
:
   state(LITERAL_STATE),
   patternLength(pattern.length()),
   i(0),
   head(),
   tail(),
   formattingInfo(),
   pattern(pattern)
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

bool PatternParser::isUnicodeIdentifierStart(logchar ch) {
  //
  //   greatly simplified version checks if
  //     character is USACII alpha or number
  //
  return (ch >= LOG4CXX_STR('A') && ch <= LOG4CXX_STR('Z')) ||
         (ch >= LOG4CXX_STR('a') && ch <= LOG4CXX_STR('z')) ||
         (ch >= LOG4CXX_STR('0') && ch <= LOG4CXX_STR('9'));
}

bool PatternParser::isUnicodeIdentifierPart(logchar ch) {
  //
  //   greatly simplified version checks if
  //     character is USACII alpha or number
  //
  return (ch >= LOG4CXX_STR('A') && ch <= LOG4CXX_STR('Z')) ||
         (ch >= LOG4CXX_STR('a') && ch <= LOG4CXX_STR('z')) ||
         (ch >= LOG4CXX_STR('0') && ch <= LOG4CXX_STR('9')) ||
         (ch == LOG4CXX_STR('_'));
}

/** Extract the converter identifier found at position i.
 *
 * After this function returns, the variable i will point to the
 * first char after the end of the converter identifier.
 *
 * If i points to a char which is not a character acceptable at the
 * start of a unicode identifier, the value null is returned.
 *
 */
LogString PatternParser::extractConverter(logchar lastChar) {

  // When this method is called, lastChar points to the first character of the
  // conersion word. For example:
  // For "%hello"     lastChar = 'h'
  // For "%-5hello"   lastChar = 'h'

        //System.out.println("lastchar is "+lastChar);

  if(!isUnicodeIdentifierStart(lastChar)) {
    return LogString();
  }

  LogString convBuf(1, lastChar);

  while ((i < patternLength)
                && isUnicodeIdentifierPart(pattern.at(i))) {
    convBuf.append(1, pattern.at(i));
    i++;
  }

  return convBuf;
}


std::vector<LogString>  PatternParser::extractOptions()
{
  std::vector<LogString> options;
  while ((i < patternLength) && (pattern.at(i) == LOG4CXX_STR('{'))) {
    size_t end = pattern.find(LOG4CXX_STR('}'), i);

    if (end != LogString::npos && end > i) {
      LogString r(pattern.substr(i + 1, end - (i + 1)));
      options.push_back(r);
       i = end+1;
    }
  }

  return options;
}

PatternConverterPtr PatternParser::parse() {
    logchar c;
    i = 0;

    while (i < patternLength) {
      c = pattern.at(i++);

      switch (state) {
      case LITERAL_STATE:

        // In literal state, the last char is always a literal.
        if (i == patternLength) {
          currentLiteral.append(1, c);

          continue;
        }

        if (c == ESCAPE_CHAR) {
          // peek at the next char.
          switch (pattern.at(i)) {
          case ESCAPE_CHAR:
            currentLiteral.append(1, c);
            i++; // move pointer

            break;

          default:

            if (currentLiteral.length() != 0) {
              PatternConverterPtr converter(
                new LiteralPatternConverter(currentLiteral));
              addToList(converter);

            }

            currentLiteral.erase(currentLiteral.begin(), currentLiteral.end());
            currentLiteral.append(1, c); // append %
            state = CONVERTER_STATE;
            formattingInfo.reset();
          }
        } else {
          currentLiteral.append(1, c);
        }

        break;

      case CONVERTER_STATE:
        currentLiteral.append(1, c);

        switch (c) {
        case '-':
          formattingInfo.leftAlign = true;

          break;

        case '.':
          state = DOT_STATE;

          break;

        default:

          if ((c >= LOG4CXX_STR('0')) && (c <= LOG4CXX_STR('9'))) {
            formattingInfo.minChar = c - LOG4CXX_STR('0');
            state = MIN_STATE;
          } else {
            finalizeConverter(c);
          }
        } // switch

        break;

      case MIN_STATE:
        currentLiteral.append(1, c);

        if ((c >= LOG4CXX_STR('0')) && (c <= LOG4CXX_STR('9'))) {
          formattingInfo.minChar = (formattingInfo.minChar * 10) + (c - LOG4CXX_STR('0'));
        } else if (c == LOG4CXX_STR('.')) {
          state = DOT_STATE;
        } else {
          finalizeConverter(c);
        }

        break;

      case DOT_STATE:
        currentLiteral.append(1, c);

        if ((c >= LOG4CXX_STR('0')) && (c <= LOG4CXX_STR('9'))) {
          formattingInfo.maxChar = c - LOG4CXX_STR('0');
          state = MAX_STATE;
        } else {
          std::basic_ostringstream<logchar> os;
          os << LOG4CXX_STR("Error occured in position ") << i
             << LOG4CXX_STR(".\n Was expecting digit, instead got char \"")
             << c + LOG4CXX_STR("\".");
          logError(os.str());
          state = LITERAL_STATE;
        }

        break;

      case MAX_STATE:
        currentLiteral.append(1, c);

        if ((c >= LOG4CXX_STR('0')) && (c <= LOG4CXX_STR('9'))) {
          formattingInfo.maxChar = (formattingInfo.maxChar * 10) + (c - LOG4CXX_STR('0'));
        } else {
          finalizeConverter(c);
          state = LITERAL_STATE;
        }

        break;
      } // switch
    }

    // while
    if (currentLiteral.length() != 0) {
      PatternConverterPtr converter(new LiteralPatternConverter(currentLiteral));
      addToList(converter);

      //LogLog.debug("Parsed LITERAL converter: \""+currentLiteral+"\".");
    }

    return head;
  }

PatternConverterPtr PatternParser::createConverter(
                                                  const LogString& converterId,
                                                  const FormattingInfo& formattingInfo,
                                                  const std::vector<LogString>& options) const {
    PatternConverterMap::const_iterator r = converterRegistry.find(converterId);
    if(r != converterRegistry.end()) {
       const Class& converterClass = Class::forName(r->second);
       PatternConverterPtr converter = converterClass.newInstance();
       converter->setFormattingInfo(formattingInfo);
       converter->setOptions(options);
       return converter;
    }

    InternalPatternConverterMap::const_iterator r2 = getGlobalRulesRegistry().find(converterId);
    if(r2 != getGlobalRulesRegistry().end()) {
       return (*r2->second)(formattingInfo, options);
    }

    PatternConverterPtr converter;
    return converter;
}


/**
 * When finalizeConverter is called 'c' is the current conversion caracter
 * and i points to the character following 'c'.
 */
void PatternParser::finalizeConverter(logchar c) {
  LogString converterId(extractConverter(c));

  std::vector<LogString> options(extractOptions());
  PatternConverterPtr pc;
  try {
      pc = createConverter(converterId, formattingInfo, options);
      if (pc == NULL) {
        std::basic_ostringstream<logchar> os;
        if (converterId.empty()) {
            os << LOG4CXX_STR("Empty conversion specifier starting at position ");
        } else {
            os << LOG4CXX_STR("Unrecognized conversion specifier [")
               << converterId
               << LOG4CXX_STR("] starting at position ");
        }
        os << i << LOG4CXX_STR(" in conversion pattern.");
        logError(os.str());
        pc = new LiteralPatternConverter(currentLiteral);
      }
  } catch(ClassNotFoundException& ex) {
      LogString msg;
      Transcoder::decode(ex.what(), msg);
      logError(msg);
      pc = new LiteralPatternConverter(currentLiteral);
  }
  currentLiteral.erase(currentLiteral.begin(), currentLiteral.end());
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

PatternParser::PatternConverterMap PatternParser::getConverterRegistry() const {
   return converterRegistry;
}

void PatternParser::setConverterRegistry(const PatternConverterMap& newRegistry) {
   converterRegistry = newRegistry;
}




// ---------------------------------------------------------------------
//                      PatternConverters
// ---------------------------------------------------------------------
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

PatternParser::DatePatternConverter::DatePatternConverter(const FormattingInfo& formattingInfo,
    const std::vector<LogString>& options)
: PatternConverter(formattingInfo), df(createDateFormat(options))
{
}

DateFormatPtr PatternParser::DatePatternConverter::createDateFormat(
    const std::vector<LogString>& options) {
    DateFormatPtr df;
    int maximumCacheValidity = 1000000;
    if (options.size() == 0) {
        df = new ISO8601DateFormat();
    } else {
       LogString dateFormatStr(options[0]);

       if(dateFormatStr.empty() ||
            StringHelper::equalsIgnoreCase(dateFormatStr,
            LOG4CXX_STR("ISO8601"), LOG4CXX_STR("iso8601"))) {
            df = new ISO8601DateFormat();
       } else if(StringHelper::equalsIgnoreCase(dateFormatStr,
            LOG4CXX_STR("ABSOLUTE"), LOG4CXX_STR("absolute"))) {
            df = new AbsoluteTimeDateFormat();
       } else if(StringHelper::equalsIgnoreCase(dateFormatStr,
            LOG4CXX_STR("DATE"), LOG4CXX_STR("date"))) {
            df = new DateTimeDateFormat();
       } else {
         if (dateFormatStr.find(LOG4CXX_STR('%')) == std::string::npos) {
            try {
               df = new SimpleDateFormat(dateFormatStr);
               maximumCacheValidity =
                  CachedDateFormat::getMaximumCacheValidity(dateFormatStr);
            } catch(IllegalArgumentException& e) {
               df = new ISO8601DateFormat();
               LogLog::warn(((LogString)
                  LOG4CXX_STR("Could not instantiate SimpleDateFormat with pattern "))
                     + dateFormatStr, e);
            }
         } else {
            df = new StrftimeDateFormat(dateFormatStr);
         }
       }
       if (options.size() >= 2) {
         TimeZonePtr tz(TimeZone::getTimeZone(options[1]));
         if (tz != NULL) {
            df->setTimeZone(tz);
         }
       }
    }
    if (maximumCacheValidity > 0) {
        df = new CachedDateFormat(df, maximumCacheValidity);
    }
    return df;
}



void PatternParser::DatePatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event, Pool& p) const
{
        df->format(sbuf, event->getTimeStamp(), p);
}

PatternParser::PropertiesPatternConverter::PropertiesPatternConverter(const FormattingInfo& formattingInfo,
   const std::vector<LogString>& options)
: PatternConverter(formattingInfo), key(getKey(options))
{
}

LogString PatternParser::PropertiesPatternConverter::getKey(const std::vector<LogString>& options) {
  if (options.size() > 0) {
    return options[0];
  }
  return LogString();
}

void PatternParser::PropertiesPatternConverter::convert(LogString& sbuf,
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


PatternParser::FullLocationPatternConverter::FullLocationPatternConverter(
    const FormattingInfo& formattingInfo,
    const std::vector<LogString>& opions)
: PatternConverter(formattingInfo)
{
}

void PatternParser::FullLocationPatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event, Pool& pool) const
{
        const LocationInfo& locInfo = event->getLocationInformation();
        Transcoder::decode(locInfo.getFileName(), sbuf);
        sbuf.append(1, LOG4CXX_STR('('));
        sbuf.append(StringHelper::toString(locInfo.getLineNumber(), pool));
        sbuf.append(1, LOG4CXX_STR(')'));
}

PatternParser::LineLocationPatternConverter::LineLocationPatternConverter(
    const FormattingInfo& formattingInfo,
    const std::vector<LogString>& opions)
: PatternConverter(formattingInfo)
{
}

void PatternParser::LineLocationPatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event, Pool& pool) const
{
        const LocationInfo& locInfo = event->getLocationInformation();
        sbuf.append(StringHelper::toString(locInfo.getLineNumber(), pool));
}

PatternParser::FileLocationPatternConverter::FileLocationPatternConverter(
    const FormattingInfo& formattingInfo,
    const std::vector<LogString>& opions)
: PatternConverter(formattingInfo)
{
}

void PatternParser::FileLocationPatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event, Pool& pool) const
{
        const LocationInfo& locInfo = event->getLocationInformation();
        Transcoder::decode(locInfo.getFileName(), sbuf);
}

PatternParser::MethodLocationPatternConverter::MethodLocationPatternConverter(
    const FormattingInfo& formattingInfo,
    const std::vector<LogString>& opions)
: PatternConverter(formattingInfo)
{
}

void PatternParser::MethodLocationPatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event, Pool& pool) const
{
        const LocationInfo& locInfo = event->getLocationInformation();
        Transcoder::decode(locInfo.getMethodName(), sbuf);
}



PatternParser::ClassNamePatternConverter::ClassNamePatternConverter(const FormattingInfo&
        formattingInfo, const std::vector<LogString>& options)
: NamedPatternConverter(formattingInfo, options)
{
}

LogString PatternParser::ClassNamePatternConverter::getFullyQualifiedName(
     const spi::LoggingEventPtr& event) const
{
    LogString sbuf;
    const LocationInfo& locInfo = event->getLocationInformation();
    Transcoder::decode(locInfo.getClassName(), sbuf);
    return sbuf;
}




PatternParser::LoggerPatternConverter::LoggerPatternConverter(const FormattingInfo&
        formattingInfo, const std::vector<LogString>& options)
: NamedPatternConverter(formattingInfo, options)
{
}

LogString PatternParser::LoggerPatternConverter::getFullyQualifiedName(
     const spi::LoggingEventPtr& event) const
{
    return event->getLoggerName();
}


PatternParser::MessagePatternConverter::MessagePatternConverter(
    const FormattingInfo& formattingInfo,
    const std::vector<LogString>& opions)
: PatternConverter(formattingInfo)
{
}

void PatternParser::MessagePatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event, Pool& pool) const
{
        sbuf.append(event->getRenderedMessage());
}

PatternParser::LineSeparatorPatternConverter::LineSeparatorPatternConverter(
    const FormattingInfo& formattingInfo,
    const std::vector<LogString>& opions)
: PatternConverter(formattingInfo)
{
}

void PatternParser::LineSeparatorPatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event, Pool& pool) const
{
        sbuf.append(LOG4CXX_EOL);
}

PatternParser::RelativeTimePatternConverter::RelativeTimePatternConverter(
    const FormattingInfo& formattingInfo,
    const std::vector<LogString>& opions)
: PatternConverter(formattingInfo)
{
}

void PatternParser::RelativeTimePatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event, Pool& pool) const
{
        formatter.format(sbuf, event->getTimeStamp(), pool);
}

PatternParser::ThreadPatternConverter::ThreadPatternConverter(
    const FormattingInfo& formattingInfo,
    const std::vector<LogString>& opions)
: PatternConverter(formattingInfo)
{
}

void PatternParser::ThreadPatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event, Pool& pool) const
{
        sbuf.append(event->getThreadName());
}



PatternParser::ThrowableInformationPatternConverter::ThrowableInformationPatternConverter(
    const FormattingInfo& formattingInfo,
    const std::vector<LogString>& opions)
: PatternConverter(formattingInfo)
{
}

void PatternParser::ThrowableInformationPatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event, Pool& pool) const
{
        sbuf.append(LOG4CXX_STR("ThrowableInformation not implemented"));
}

PatternParser::NDCPatternConverter::NDCPatternConverter(
    const FormattingInfo& formattingInfo,
    const std::vector<LogString>& opions)
: PatternConverter(formattingInfo)
{
}

void PatternParser::NDCPatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event, Pool& pool) const
{
        sbuf.append(event->getNDC());
}

PatternParser::LevelPatternConverter::LevelPatternConverter(
    const FormattingInfo& formattingInfo,
    const std::vector<LogString>& opions)
: PatternConverter(formattingInfo)
{
}

void PatternParser::LevelPatternConverter::convert(LogString& sbuf,
        const spi::LoggingEventPtr& event, Pool& pool) const
{
        sbuf.append(event->getLevel()->toString());
}
