/***************************************************************************
                          loglog.h  -  class LogLog
                             -------------------
    begin                : jeu avr 17 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#ifndef _LOG4CXX_HELPERS_LOG_LOG_H
#define _LOG4CXX_HELPERS_LOG_LOG_H

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/exception.h>

namespace log4cxx
{
	namespace helpers
	{
		/**
		This class used to output log statements from within the log4cxx package.

		<p>Log4cxx components cannot make log4cxx logging calls. However, it is
		sometimes useful for the user to learn about what log4cxx is
		doing. You can enable log4cxx internal logging by calling the
		<b>#setInternalDebugging</b> method.

		<p>All log4cxx internal debug calls go to standard output
		where as internal error messages are sent to
		standard error output. All internal messages are prepended with
		the string "log4cxx: ".
		*/
		class LogLog
		{
		public:
			/**
			Defining this value makes log4j print log4j-internal debug
			statements to <code>System.out</code>.

			<p> The value of this string is <b>log4j.debug</b>.

			<p>Note that the search for all option names is case sensitive.  */
			static String DEBUG_KEY;



		protected:
			static bool debugEnabled;  

		  /**
			 In quietMode not even errors generate any output.
		   */
			static bool quietMode;

		public:
			/**
			Allows to enable/disable log4cxx internal logging.
			*/
			static void setInternalDebugging(bool enabled);
			
			/**
			This method is used to output log4cxx internal debug
			statements. Output goes to the standard output.
			*/
			static void debug(const String& msg);
			static void debug(const String& msg, Exception& e);
			
			/**
			This method is used to output log4cxx internal error
			statements. There is no way to disable error statements.
			Output goes to stderr.
			*/
			static void error(const String& msg);
			static void error(const String& msg, Exception& e);

			/**
			In quite mode LogLog generates strictly no output, not even
			for errors. 

			@param quietMode <code>true</code> for no output.
			*/
			static void setQuietMode(bool quietMode);

			/**
			This method is used to output log4cxx internal warning
			statements. There is no way to disable warning statements.
			Output goes to stderr.
			*/
			static void warn(const String&  msg);
			static void warn(const String&  msg, Exception& e);
		};
	}; // namespace helpers
}; // namespace log4cxx

#define LOGLOG_DEBUG(log) { \
	StringBuffer oss; \
	oss << log; \
	log4cxx::helpers::LogLog::debug(oss.str()) ; }

#define LOGLOG_WARN(log) { \
	StringBuffer oss; \
	oss << log; \
	log4cxx::helpers::LogLog::warn(oss.str()) ; }

#define LOGLOG_ERROR(log) { \
	StringBuffer oss; \
	oss << log; \
	log4cxx::helpers::LogLog::warn(oss.str()); }

#endif //_LOG4CXX_HELPERS_LOG_LOG_H
