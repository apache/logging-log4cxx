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
#ifndef _LOG4CXX_FILTER_MAPFILTER_H
#define _LOG4CXX_FILTER_MAPFILTER_H

#include <log4cxx/spi/filter.h>

namespace LOG4CXX_NS
{
namespace filter
{

/**
 * A Filter that operates on the current thread's MDC map.

 For example, to exclude entries from the log where the context
 has "user.name" set to "test2" and "user.ip" is "127.0.0.1":
 * <pre>
 * &lt;filter class="MapFilter"&gt;
 *     &lt;param name="user.ip"       value="127.0.0.1" /&gt;
 *     &lt;param name="user.name"     value="test2"     /&gt;
 *     &lt;param name="Operator"      value="AND"       /&gt;
 *     &lt;param name="AcceptOnMatch" value="false"     /&gt;
 * &lt;/filter&gt;
 * </pre>
 */
class LOG4CXX_EXPORT MapFilter: public LOG4CXX_NS::spi::Filter
{
		typedef std::map < LogString, LogString > KeyVals;

	private:
		struct MapFilterPrivate;

	public:
		DECLARE_LOG4CXX_OBJECT(MapFilter)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(MapFilter)
		LOG4CXX_CAST_ENTRY_CHAIN(LOG4CXX_NS::spi::Filter)
		END_LOG4CXX_CAST_MAP()

		MapFilter();
		~MapFilter();

		/**
		\copybrief spi::OptionHandler::setOption()

		Supported options | Supported values | Default value
		-------------- | ---------------- | ---------------
		Operator | (\ref andOrOne "1") | Or
		AcceptOnMatch | True,False | True
		{anyKey} | {anyValue} | -

		\anchor andOrOne (1) If "And", the MDC must contain all configured key-value pairs,
		otherwise only one configured key-value pair needs to match. 
		*/
		void setOption(const LogString& option, const LogString& value) override;

		void setKeyValue(const LogString& strKey, const LogString& strValue);

		const LogString& getValue(const LogString& strKey) const;

		void setAcceptOnMatch(bool acceptOnMatch1);

		bool getAcceptOnMatch() const;

		bool getMustMatchAll() const;

		void setMustMatchAll(bool mustMatchAll1);

		/**
		Returns {@link log4cxx::spi::Filter#NEUTRAL NEUTRAL}
		is there is no string match.
		*/
		FilterDecision decide(const spi::LoggingEventPtr& event) const override;
}; // class MapFilter

LOG4CXX_PTR_DEF(MapFilter);

} // namespace filter
} // namespace log4cxx


#endif // _LOG4CXX_FILTER_MAPFILTER_H
