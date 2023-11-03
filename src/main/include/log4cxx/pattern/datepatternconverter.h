/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _LOG4CXX_PATTERN_DATE_PATTERN_CONVERTER
#define _LOG4CXX_PATTERN_DATE_PATTERN_CONVERTER

#include <log4cxx/pattern/loggingeventpatternconverter.h>
#include <log4cxx/helpers/cacheddateformat.h>
#include <log4cxx/helpers/date.h>
#include <vector>

namespace LOG4CXX_NS
{
namespace pattern
{


/**
 * Convert and format a date or timestamp into a string.
 */
class LOG4CXX_EXPORT DatePatternConverter : public LoggingEventPatternConverter
{
		struct DatePatternConverterPrivate;

		/**
		 * Obtains an instance of pattern converter.
		 * @param options options, may be null.
		 * @return instance of pattern converter.
		 */
		static helpers::DateFormatPtr getDateFormat(const OptionsList& options);
	public:
		DECLARE_LOG4CXX_PATTERN(DatePatternConverter)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(DatePatternConverter)
		LOG4CXX_CAST_ENTRY_CHAIN(LoggingEventPatternConverter)
		END_LOG4CXX_CAST_MAP()

		/**
		 * An object that can convert a date or timestamp to the format
		 * described by the conversion specifier in the first element in \c options.
		 *
		 * If the conversion specifier contains a \% character,
		 * the date is formated using <a href="https://en.cppreference.com/w/cpp/chrono/c/strftime">strftime</a>.
		 *
		 * Otherwise the conversion specifier must be a pattern compatible with
		 * java.text.SimpleDateFormat, "ABSOLUTE", "DATE" or "ISO8601".
		 * For example, "HH:mm:ss,SSS", "dd MMM yyyy HH:mm:ss,SSS" or "DATE".
		 *
		 * ISO8601 format is assumed if the first element in \c options missing or empty.
		 *
		 * If \c options has a second element, it is assumed to be a time zone specifier,
		 * for example, "GMT-6"
		 */
		DatePatternConverter(const OptionsList& options);

		~DatePatternConverter();

		/**
		 * \copydoc #DatePatternConverter::DatePatternConverter()
		 */
		static PatternConverterPtr newInstance(
			const std::vector<LogString>& options);

		/**
		 * Append to \c output a textual version of the timestamp in \c event.
		 */
		void format(const spi::LoggingEventPtr& event,
			LogString& output,
			helpers::Pool& p) const override;

		/**
		 * Append to \c output a textual version of the date or timestamp in \c obj.
		 *
		 * Nothing is added to \c output if \c obj does not point to a Date or spi::LoggingEvent.
		 */
		void format(const helpers::ObjectPtr& obj,
			LogString& output,
			helpers::Pool& p) const override;

		/**
		 * Append to \c toAppendTo a textual version of \c date.
		 */
		void format(const helpers::DatePtr& date,
			LogString& toAppendTo,
			helpers::Pool& p) const;
};

LOG4CXX_PTR_DEF(DatePatternConverter);

}
}
#endif

