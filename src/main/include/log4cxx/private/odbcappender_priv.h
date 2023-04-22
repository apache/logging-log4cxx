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

#ifndef LOG4CXX_ODBCAPPENDER_PRIV
#define LOG4CXX_ODBCAPPENDER_PRIV

#include <log4cxx/db/odbcappender.h>
#include <log4cxx/pattern/loggingeventpatternconverter.h>
#include "appenderskeleton_priv.h"

namespace log4cxx
{
namespace db
{

struct ODBCAppender::ODBCAppenderPriv : public AppenderSkeleton::AppenderSkeletonPrivate
{
	ODBCAppenderPriv()
		: AppenderSkeletonPrivate()
		, connection(0)
		, env(0)
		, preparedStatement(0)
		, max_message_character_count(1000)
		, max_file_path_character_count(300)
		, bufferSize(1)
		{}

	/**
	* URL of the DB for default connection handling
	*/
	LogString databaseURL;

	/**
	* User to connect as for default connection handling
	*/
	LogString databaseUser;

	/**
	* User to use for default connection handling
	*/
	LogString databasePassword;

	/**
	* Connection used by default.  The connection is opened the first time it
	* is needed and then held open until the appender is closed (usually at
	* garbage collection).  This behavior is best modified by creating a
	* sub-class and overriding the <code>getConnection</code> and
	* <code>closeConnection</code> methods.
	*/
	SQLHDBC connection;
	SQLHENV env;

	/**
	* Stores the string given to the pattern layout for conversion into a SQL
	* statement, eg: insert into LogTable (Thread, File, Message) values
	* ("%t", "%F", "%m")
	*
	* Be careful of quotes in your messages!
	*
	* Also see PatternLayout.
	*/
	LogString sqlStatement;

	/**
	* The bound column names, converters and buffers
	*/
	std::vector<LogString> mappedName;
	size_t max_message_character_count;
	size_t max_file_path_character_count;
	using MappedValue = std::tuple<pattern::LoggingEventPatternConverterPtr, wchar_t*, size_t>;
	std::vector<MappedValue> parameterValue;
	SQLHSTMT preparedStatement;
	void setPreparedStatement(SQLHDBC con, helpers::Pool& p);
	void setParameterValues(const spi::LoggingEventPtr& event, helpers::Pool& p);

	/**
	* size of LoggingEvent buffer before writing to the database.
	* Default is 1.
	*/
	size_t bufferSize;

	/**
	* ArrayList holding the buffer of Logging Events.
	*/
	std::vector<spi::LoggingEventPtr> buffer;
};

}
}

#endif /* LOG4CXX_ODBCAPPENDER_PRIV */
