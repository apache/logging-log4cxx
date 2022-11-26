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

#ifndef _LOG4CXX_DB_ODBC_APPENDER_H
#define _LOG4CXX_DB_ODBC_APPENDER_H

#include <log4cxx/log4cxx.h>

#include <log4cxx/helpers/exception.h>
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/spi/loggingevent.h>
#include <list>
#include <memory>

namespace log4cxx
{
namespace db
{
class LOG4CXX_EXPORT SQLException : public log4cxx::helpers::Exception
{
	public:
		SQLException(short fHandleType,
			void* hInput, const char* prolog,
			log4cxx::helpers::Pool& p);
		SQLException(const char* msg);
		SQLException(const SQLException& src);
	private:
		const char* formatMessage(short fHandleType,
			void* hInput, const char* prolog,
			log4cxx::helpers::Pool& p);
};

/**
<p><b>WARNING: This version of ODBCAppender
is very likely to be completely replaced in the future. Moreoever,
it does not log exceptions.</b> </p>

The ODBCAppender provides for sending log events to a database.


<p>Each append call adds to an <code>ArrayList</code> buffer.  When
the buffer is filled each log event is placed in a sql statement
(configurable) and executed.

<b>BufferSize</b>, <b>db URL</b>, <b>User</b>, & <b>Password</b> are
configurable options in the standard log4j ways.

<p>The <code>setSql(String sql)</code> sets the SQL statement to be
used for logging -- this statement is sent to a
<code>PatternLayout</code> (either created automaticly by the
appender or added by the user).  Therefore by default all the
conversion patterns in <code>PatternLayout</code> can be used
inside of the statement.  (see the test cases for examples)

<p>Overriding the {@link #getLogStatement} method allows more
explicit control of the statement used for logging.

<p>For use as a base class:

<ul>

<li>Override getConnection() to pass any connection
you want.  Typically this is used to enable application wide
connection pooling.

<li>Override closeConnection -- if
you override getConnection make sure to implement
<code>closeConnection</code> to handle the connection you
generated.  Typically this would return the connection to the
pool it came from.

<li>Override getLogStatement to
produce specialized or dynamic statements. The default uses the
sql option value.

</ul>
*/

class LOG4CXX_EXPORT ODBCAppender : public AppenderSkeleton
{
	public:
		DECLARE_LOG4CXX_OBJECT(ODBCAppender)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(ODBCAppender)
		LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
		END_LOG4CXX_CAST_MAP()

		typedef void* SQLHDBC;
		typedef void* SQLHENV;
		typedef void* SQLHANDLE;
		typedef short SQLSMALLINT;

		ODBCAppender();
		virtual ~ODBCAppender();

		/**
		Set options
		*/
		void setOption(const LogString& option, const LogString& value) override;

		/**
		Activate the specified options.
		*/
		void activateOptions(helpers::Pool& p) override;

		/**
		* Adds the event to the buffer.  When full the buffer is flushed.
		*/
		void append(const spi::LoggingEventPtr& event, helpers::Pool&) override;

		/**
		* By default getLogStatement sends the event to the required Layout object.
		* The layout will format the given pattern into a workable SQL string.
		*
		* Overriding this provides direct access to the LoggingEvent
		* when constructing the logging statement.
		*
		*/
	protected:
		LogString getLogStatement(const spi::LoggingEventPtr& event,
			helpers::Pool& p) const;

		/**
		*
		* Override this to provide an alertnate method of getting
		* connections (such as caching).  One method to fix this is to open
		* connections at the start of flushBuffer() and close them at the
		* end.  I use a connection pool outside of ODBCAppender which is
		* accessed in an override of this method.
		* */
		virtual void execute(const LogString& sql,
			log4cxx::helpers::Pool& p) /*throw(SQLException)*/;

		/**
		* Override this to return the connection to a pool, or to clean up the
		* resource.
		*
		* The default behavior holds a single connection open until the appender
		* is closed (typically when garbage collected).
		*/
		virtual void closeConnection(SQLHDBC con);

		/**
		* Override this to link with your connection pooling system.
		*
		* By default this creates a single connection which is held open
		* until the object is garbage collected.
		*/
		virtual SQLHDBC getConnection(log4cxx::helpers::Pool& p) /*throw(SQLException)*/;

		/**
		* Closes the appender, flushing the buffer first then closing the default
		* connection if it is open.
		*/
	public:
		void close() override;

		/**
		* loops through the buffer of LoggingEvents, gets a
		* sql string from getLogStatement() and sends it to execute().
		* Errors are sent to the errorHandler.
		*
		* If a statement fails the LoggingEvent stays in the buffer!
		*/
		virtual void flushBuffer(log4cxx::helpers::Pool& p);

		/**
		* ODBCAppender requires a layout.
		* */
		bool requiresLayout() const override
		{
			return true;
		}

		/**
		* Set pre-formated statement eg: insert into LogTable (msg) values ("%m")
		*/
		void setSql(const LogString& s);

		/**
		* Returns pre-formated statement eg: insert into LogTable (msg) values ("%m")
		*/
		const LogString& getSql() const;


		void setUser(const LogString& user);

		void setURL(const LogString& url);

		void setPassword(const LogString& password);

		void setBufferSize(size_t newBufferSize);

		const LogString& getUser() const;

		const LogString& getURL() const;

		const LogString& getPassword() const;

		size_t getBufferSize() const;
	private:
		ODBCAppender(const ODBCAppender&);
		ODBCAppender& operator=(const ODBCAppender&);
#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR_T || defined(WIN32) || defined(_WIN32)
		static void encode(wchar_t** dest, const LogString& src,
			log4cxx::helpers::Pool& p);
#endif
		static void encode(unsigned short** dest, const LogString& src,
			log4cxx::helpers::Pool& p);

	protected:
		struct ODBCAppenderPriv;
}; // class ODBCAppender
LOG4CXX_PTR_DEF(ODBCAppender);

} // namespace db
} // namespace log4cxx

#endif // _LOG4CXX_DB_ODBC_APPENDER_H
