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

#include <log4cxx/logstring.h>
#include <log4cxx/helpers/loader.h>
#include <log4cxx/appender.h>
#include <log4cxx/spi/filter.h>
#include <log4cxx/spi/loggerfactory.h>
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/helpers/object.h>
#include <log4cxx/spi/errorhandler.h>
#include <log4cxx/helpers/fileinputstream.h>
#include <log4cxx/spi/repositoryselector.h>
#include <log4cxx/spi/appenderattachable.h>
#ifndef LOG4CXX_FOUNDATION_ONLY
#if LOG4CXX_HAS_DOMCONFIGURATOR
#include <log4cxx/helpers/xml.h>
#endif
#include <log4cxx/filter/denyallfilter.h>
#include <log4cxx/spi/triggeringeventevaluator.h>
using namespace LOG4CXX_NS::filter;
#endif // LOG4CXX_FOUNDATION_ONLY

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::spi;

IMPLEMENT_LOG4CXX_OBJECT(Object)
IMPLEMENT_LOG4CXX_OBJECT(OptionHandler)
IMPLEMENT_LOG4CXX_OBJECT(ErrorHandler)
IMPLEMENT_LOG4CXX_OBJECT(Appender)
IMPLEMENT_LOG4CXX_OBJECT(AppenderAttachable)
IMPLEMENT_LOG4CXX_OBJECT(Filter)
IMPLEMENT_LOG4CXX_OBJECT(LoggerFactory)
IMPLEMENT_LOG4CXX_OBJECT(LoggerRepository)
IMPLEMENT_LOG4CXX_OBJECT(RepositorySelector)
#ifndef LOG4CXX_FOUNDATION_ONLY
#if LOG4CXX_HAS_DOMCONFIGURATOR
IMPLEMENT_LOG4CXX_OBJECT(XMLDOMNode)
IMPLEMENT_LOG4CXX_OBJECT(XMLDOMDocument)
IMPLEMENT_LOG4CXX_OBJECT(XMLDOMElement)
IMPLEMENT_LOG4CXX_OBJECT(XMLDOMNodeList)
#endif
IMPLEMENT_LOG4CXX_OBJECT(DenyAllFilter)
IMPLEMENT_LOG4CXX_OBJECT(TriggeringEventEvaluator)
#endif // LOG4CXX_FOUNDATION_ONLY

const Class& Loader::loadClass(const LogString& clazz)
{
	return Class::forName(clazz);
}


InputStreamPtr Loader::getResourceAsStream(const LogString& name)
{

	try
	{
		return std::make_shared<FileInputStream>(name);
	}
	catch (const IOException&)
	{
	}

	return 0;
}
