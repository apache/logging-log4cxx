/*
 * Copyright 2003,2004 The Apache Software Foundation.
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
#include <log4cxx/helpers/patternconverter.h>

class apr_pool_t;

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
                protected:
                        int state;
                        LogString currentLiteral;
                        int patternLength;
                        int i;
                        PatternConverterPtr head;
                        PatternConverterPtr tail;
                        FormattingInfo formattingInfo;
                        LogString pattern;
                        LogString timeZone;

                public:
                        PatternParser(const LogString& pattern, const LogString& timeZone);

                private:
                        void addToList(PatternConverterPtr& pc);

                protected:
                        LogString extractOption();

                        /**
                        The option is expected to be in decimal and positive. In case of
                        error, zero is returned.  */
                        int extractPrecisionOption();

                public:
                        PatternConverterPtr parse();

                protected:
                        void finalizeConverter(logchar c);

                        void addConverter(PatternConverterPtr& pc);

                // ---------------------------------------------------------------------
                //                      PatternConverters
                // ---------------------------------------------------------------------
                private:
                        class LOG4CXX_EXPORT BasicPatternConverter : public PatternConverter
                        {
                        private:
                                int type;
                        public:
                                BasicPatternConverter(const FormattingInfo& formattingInfo, int type);
                                virtual void convert(LogString& sbuf,
                                        const spi::LoggingEventPtr& event,
                                        apr_pool_t* pool) const;
                        };

                        class LOG4CXX_EXPORT LiteralPatternConverter : public PatternConverter
                        {
                        private:
                                LogString literal;

                        public:
                                LiteralPatternConverter(const LogString& value);
                                virtual void convert(LogString& sbuf,
                                        const spi::LoggingEventPtr& event,
                                        apr_pool_t* pool) const;
                        private:
                                //   prevent copy and assignment
                                LiteralPatternConverter(const LiteralPatternConverter&);
                                LiteralPatternConverter& operator=(const LiteralPatternConverter&);
                        };

                        class LOG4CXX_EXPORT DatePatternConverter : public PatternConverter
                        {
                        private:
                                DateFormat * df;

                        public:
                                DatePatternConverter(const FormattingInfo& formattingInfo,
                                        DateFormat * df);
                                ~DatePatternConverter();

                                virtual void convert(LogString& sbuf,
                                        const spi::LoggingEventPtr& event,
                                        apr_pool_t* pool) const;

                        private:
                                //   prevent copy and assignment
                                DatePatternConverter(const DatePatternConverter&);
                                DatePatternConverter& operator=(const DatePatternConverter&);
                        };

                        class LOG4CXX_EXPORT MDCPatternConverter : public PatternConverter
                        {
                        private:
                                LogString key;

                        public:
                                MDCPatternConverter(const FormattingInfo& formattingInfo,
                                        const LogString& key);
                                virtual void convert(LogString& sbuf,
                                        const spi::LoggingEventPtr& event,
                                        apr_pool_t* pool) const;
                        private:
                                //   prevent copy and assignment
                                MDCPatternConverter(const MDCPatternConverter&);
                                MDCPatternConverter& operator=(const MDCPatternConverter&);
                        };

                        class LOG4CXX_EXPORT LocationPatternConverter : public PatternConverter
                        {
                        private:
                                int type;

                        public:
                                LocationPatternConverter(const FormattingInfo& formattingInfo, int type);
                                virtual void convert(LogString& sbuf,
                                        const spi::LoggingEventPtr& event,
                                        apr_pool_t* pool) const;
                        };

                        class LOG4CXX_EXPORT CategoryPatternConverter : public PatternConverter
                        {
                        private:
                                int precision;

                        public:
                                CategoryPatternConverter(const FormattingInfo& formattingInfo,
                                        int precision);
                                virtual void convert(LogString& sbuf,
                                        const spi::LoggingEventPtr& event,
                                        apr_pool_t* pool) const;
                        };
                }; // class PatternParser
        }  // namespace helpers
} // namespace log4cxx

#endif //_LOG4CXX_HELPER_PATTERN_PARSER_H
