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

#include <stdlib.h>
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/helpers/object.h>
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/xml/domconfigurator.h>

namespace log4cxx {

class NullWriterAppender : public log4cxx::AppenderSkeleton {
public:
	DECLARE_LOG4CXX_OBJECT(NullWriterAppender)
	BEGIN_LOG4CXX_CAST_MAP()
	LOG4CXX_CAST_ENTRY(NullWriterAppender)
	LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
	END_LOG4CXX_CAST_MAP()

	NullWriterAppender(){}

	virtual void close(){}

	virtual bool requiresLayout() const {
		return false;
	}

	virtual void append(const spi::LoggingEventPtr& event, log4cxx::helpers::Pool& p){
		// This gets called whenever there is a valid event for our appender.
	}

	virtual void activateOptions(log4cxx::helpers::Pool& /* pool */) {
		// Given all of our options, do something useful(e.g. open a file)
	}

	virtual void setOption(const LogString& option, const LogString& value){
		if (helpers::StringHelper::equalsIgnoreCase(option,
										   LOG4CXX_STR("SOMEVALUE"), LOG4CXX_STR("somevalue"))){
			// Do something with the 'value' here.
		}
	}
};

IMPLEMENT_LOG4CXX_OBJECT(NullWriterAppender)

}

int main( int argc, char** argv ){
	log4cxx::xml::DOMConfigurator::configure( "custom-appender.xml" );

	log4cxx::LoggerPtr rootLogger = log4cxx::Logger::getRootLogger();
	log4cxx::LoggerPtr nullLogger = log4cxx::Logger::getLogger( "NullLogger" );

	LOG4CXX_INFO( rootLogger, "This is some root message" );
	LOG4CXX_INFO( nullLogger, "This message will be discarded" );
}
