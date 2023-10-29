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

#ifndef _LOG4CXX_PATTERN_LEVEL_PATTERN_CONVERTER
#define _LOG4CXX_PATTERN_LEVEL_PATTERN_CONVERTER

#include <log4cxx/pattern/loggingeventpatternconverter.h>

namespace LOG4CXX_NS
{
namespace pattern
{


/**
 * Return the event's level in a StringBuffer.
 *
 *
 *
 */
class LOG4CXX_EXPORT LevelPatternConverter : public LoggingEventPatternConverter
{
	public:
		DECLARE_LOG4CXX_PATTERN(LevelPatternConverter)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(LevelPatternConverter)
		LOG4CXX_CAST_ENTRY_CHAIN(LoggingEventPatternConverter)
		END_LOG4CXX_CAST_MAP()

		LevelPatternConverter();

		/**
		 * Obtains an instance of pattern converter.
		 * @param options options, may be null.
		 * @return instance of pattern converter.
		 */
		static PatternConverterPtr newInstance(
			const std::vector<LogString>& options);

		using LoggingEventPatternConverter::format;

		void format(const spi::LoggingEventPtr& event,
			LogString& toAppendTo,
			helpers::Pool& p) const override;

		LogString getStyleClass(const 	helpers::ObjectPtr& e) const override;
};
}
}
#endif

