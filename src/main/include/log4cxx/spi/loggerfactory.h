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

#ifndef _LOG4CXX_SPI_LOGGERFACTORY_H
#define _LOG4CXX_SPI_LOGGERFACTORY_H

#include <log4cxx/logger.h>

namespace LOG4CXX_NS
{

namespace spi
{
/**
Implement this interface to create new instances of Logger or
a sub-class of Logger.
*/
class LOG4CXX_EXPORT LoggerFactory : public virtual helpers::Object
{
	public:
#if LOG4CXX_ABI_VERSION <= 15
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(LoggerFactory)
#else
		DECLARE_LOG4CXX_OBJECT(LoggerFactory)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(LoggerFactory)
		END_LOG4CXX_CAST_MAP()
#endif
		virtual ~LoggerFactory() {}

#if LOG4CXX_ABI_VERSION <= 15
		[[ deprecated( "Pool is no longer required" ) ]]
		virtual LoggerPtr makeNewLoggerInstance(helpers::Pool& pool, const LogString& name) const = 0;

		LoggerPtr makeNewLoggerInstance(const LogString& name) const;
#else
		virtual LoggerPtr makeNewLoggerInstance(const LogString& name) const;
#endif
};


}  // namespace spi
} // namesapce log4cxx

#endif //_LOG4CXX_SPI_LOGGERFACTORY_H
