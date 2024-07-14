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

#if LOG4CXX_ABI_VERSION <= 15
#include <log4cxx/defaultloggerfactory.h>
#else
#include <log4cxx/spi/loggerfactory.h>
#endif

using namespace LOG4CXX_NS;
using namespace spi;

#if LOG4CXX_ABI_VERSION <= 15
IMPLEMENT_LOG4CXX_OBJECT(DefaultLoggerFactory)

LoggerPtr DefaultLoggerFactory::makeNewLoggerInstance(
	helpers::Pool& pool,
	const LogString& name) const
{
	return std::make_shared<Logger>(name);
}
#endif

LoggerPtr LoggerFactory::makeNewLoggerInstance(const LogString& name) const
{
	return std::make_shared<Logger>(name);
}

