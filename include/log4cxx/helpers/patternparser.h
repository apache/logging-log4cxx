/*
 * Copyright 2003,2005 The Apache Software Foundation.
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

#ifndef _LOG4CXX_HELPER_PATTERN_PARSER_H
#define _LOG4CXX_HELPER_PATTERN_PARSER_H

#include <log4cxx/logstring.h>
#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/helpers/formattinginfo.h>
#include <log4cxx/helpers/namedpatternconverter.h>
#include <log4cxx/helpers/dateformat.h>
#include <log4cxx/helpers/relativetimedateformat.h>
#include <map>
#include <vector>

#define DEFINE_PATTERN_CONVERTER(classname)                   \
class LOG4CXX_EXPORT classname : public PatternConverter {    \
public:                                                       \
classname(const FormattingInfo& formattingInfo,               \
          const std::vector<LogString>& options);             \
virtual void convert(LogString& sbuf,                         \
              const spi::LoggingEventPtr& event,              \
              log4cxx::helpers::Pool& pool) const;            \
static PatternConverter* newInstance(                         \
          const FormattingInfo& formattingInfo,               \
          const std::vector<LogString>& options) {            \
          return new classname(formattingInfo, options);  }   \
private:                                                      \
classname(const classname&);                                  \
classname& operator=(const classname&);

#define END_DEFINE_PATTERN_CONVERTER(classname)          };


#define DEFINE_NAMED_PATTERN_CONVERTER(classname)                   \
class LOG4CXX_EXPORT classname : public NamedPatternConverter {    \
public:                                                       \
classname(const FormattingInfo& formattingInfo,               \
          const std::vector<LogString>& options);             \
virtual LogString getFullyQualifiedName(                      \
    const spi::LoggingEventPtr& event) const;                 \
static PatternConverter* newInstance(                         \
          const FormattingInfo& formattingInfo,               \
          const std::vector<LogString>& options) {            \
          return new classname(formattingInfo, options);  }   \
private:                                                      \
classname(const classname&);                                  \
classname& operator=(const classname&);

#define END_DEFINE_NAMED_PATTERN_CONVERTER(classname)          };


namespace log4cxx
{
        namespace spi
        {
                class LoggingEvent;
                typedef helpers::ObjectPtrT<LoggingEvent> LoggingEventPtr;
        }

        namespace helpers
        {

                class DateFormat;

        /**
        Most of the work of the PatternLayout class
        is delegated to the PatternParser class.

        <p>It is this class that parses conversion patterns and creates
        a chained list of {@link helpers::OptionConverter OptionConverters}.
        */
                class LOG4CXX_EXPORT PatternParser
                {
                public:
                typedef PatternConverter* (*PatternConverterFactory)(
                     const FormattingInfo& info,
                     const std::vector<LogString>& options);
                typedef std::map<LogString, PatternConverterFactory> InternalPatternConverterMap;
                typedef std::map<LogString, LogString> PatternConverterMap;

                private:
                  enum {
                      LITERAL_STATE = 0,
                      CONVERTER_STATE = 1,
                      DOT_STATE = 3,
                      MIN_STATE = 4,
                      MAX_STATE = 5 } state;

                  static const InternalPatternConverterMap& getGlobalRulesRegistry();

                  LogString currentLiteral;
                  LogString::size_type patternLength;
                  LogString::size_type i;
                  PatternConverterPtr head;
                  PatternConverterPtr tail;
                  FormattingInfo formattingInfo;
                  LogString pattern;

                  /**
                   * Additional rules for this particular instance.
                   * key: the conversion word (as String)
                   * value: the pattern converter class (as String)
                   */
                  PatternConverterMap converterRegistry;



                public:
                        PatternParser(const LogString& pattern);

                private:
                        void addToList(PatternConverterPtr& pc);
                        LogString extractConverter(logchar lastChar);
                        std::vector<LogString> extractOptions();


                public:
                        PatternConverterPtr parse();

                        PatternConverterMap getConverterRegistry() const;
                        void setConverterRegistry(const PatternConverterMap&);


                private:
                        PatternConverterPtr createConverter(const LogString& converterId,
                           const FormattingInfo& formattingInfo,
                           const std::vector<LogString>& options) const;

                        void finalizeConverter(logchar c);

                        void addConverter(PatternConverterPtr& pc);

                        bool isUnicodeIdentifierStart(logchar ch);
                        bool isUnicodeIdentifierPart(logchar ch);

                        static void logError(const LogString& msg);
                        static void logWarn(const LogString& msg);


                // ---------------------------------------------------------------------
                //                      PatternConverters
                // ---------------------------------------------------------------------
                private:

                        class LOG4CXX_EXPORT LiteralPatternConverter : public PatternConverter {
                        public:
                            LiteralPatternConverter(const LogString& literal);
                            virtual void convert(LogString& sbuf,
                                      const spi::LoggingEventPtr& event,
                                      log4cxx::helpers::Pool& pool) const;
                        private:
                            LiteralPatternConverter(LiteralPatternConverter&);
                            LiteralPatternConverter& operator=(LiteralPatternConverter&);
                            LogString literal;
                        };


                        DEFINE_PATTERN_CONVERTER(DatePatternConverter)
                            DateFormatPtr df;
                            static DateFormatPtr createDateFormat(const std::vector<LogString>& options);
                        END_DEFINE_PATTERN_CONVERTER(DatePatternConverter)

                        DEFINE_PATTERN_CONVERTER(FullLocationPatternConverter)
                        END_DEFINE_PATTERN_CONVERTER(FullLocationPatternConverter)

                        DEFINE_PATTERN_CONVERTER(LineLocationPatternConverter)
                        END_DEFINE_PATTERN_CONVERTER(LineLocationPatternConverter)

                        DEFINE_PATTERN_CONVERTER(FileLocationPatternConverter)
                        END_DEFINE_PATTERN_CONVERTER(FileLocationPatternConverter)

                        DEFINE_PATTERN_CONVERTER(MethodLocationPatternConverter)
                        END_DEFINE_PATTERN_CONVERTER(MethodLocationPatternConverter)

                        DEFINE_NAMED_PATTERN_CONVERTER(ClassNamePatternConverter)
                        END_DEFINE_NAMED_PATTERN_CONVERTER(ClassNamePatternConverter)

                        DEFINE_NAMED_PATTERN_CONVERTER(LoggerPatternConverter)
                        END_DEFINE_NAMED_PATTERN_CONVERTER(LoggerPatternConverter)

                        DEFINE_PATTERN_CONVERTER(MessagePatternConverter)
                        END_DEFINE_PATTERN_CONVERTER(MessagePatternConverter)

                        DEFINE_PATTERN_CONVERTER(LineSeparatorPatternConverter)
                        END_DEFINE_PATTERN_CONVERTER(LineSeparatorPatternConverter)

                        DEFINE_PATTERN_CONVERTER(LevelPatternConverter)
                        END_DEFINE_PATTERN_CONVERTER(LevelPatternConverter)

                        DEFINE_PATTERN_CONVERTER(RelativeTimePatternConverter)
                            RelativeTimeDateFormat formatter;
                        END_DEFINE_PATTERN_CONVERTER(RelativeTimePatternConverter)

                        DEFINE_PATTERN_CONVERTER(ThreadPatternConverter)
                        END_DEFINE_PATTERN_CONVERTER(ThreadPatternConverter)

                        DEFINE_PATTERN_CONVERTER(NDCPatternConverter)
                        END_DEFINE_PATTERN_CONVERTER(NDCPatternConverter)

                        DEFINE_PATTERN_CONVERTER(PropertiesPatternConverter)
                          LogString key;
                          static LogString getKey(const std::vector<LogString>& options);
                        END_DEFINE_PATTERN_CONVERTER(PropertiesPatternConverter)

                        DEFINE_PATTERN_CONVERTER(ThrowableInformationPatternConverter)
                        END_DEFINE_PATTERN_CONVERTER(ThrowableInformationPatternConverter)


                }; // class PatternParser
        }  // namespace helpers
} // namespace log4cxx

#undef DEFINE_PATTERN_CONVERTER
#undef END_DEFINE_PATTERN_CONVERTER
#undef DEFINE_NAMED_PATTERN_CONVERTER
#undef END_DEFINE_NAMED_PATTERN_CONVERTER

#endif //_LOG4CXX_HELPER_PATTERN_PARSER_H
