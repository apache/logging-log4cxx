/***************************************************************************
                          level.h  -  class Level
                             -------------------
    begin                : mer avr 16 2003
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
 
#include <log4cxx/helpers/tchar.h>
#include <limits.h>

#ifndef _LOG4CXX_LEVEL_H
#define _LOG4CXX_LEVEL_H

namespace log4cxx
{
	/**
	Defines the minimum set of levels recognized by the system, that is
	<code>OFF</code>, <code>FATAL</code>, <code>ERROR</code>,
	<code>WARN</code>, <code>INFO</code, <code>DEBUG</code> and
	<code>ALL</code>.
	<p>The <code>Level</code> class may be subclassed to define a larger
	level set.
	*/
	class Level
	{
		/**
		Instantiate a Level object.
		*/
	public:
		Level(int level, tstring levelStr, int syslogEquivalent);


		/**
		Convert the string passed as argument to a level. If the
		conversion fails, then this method returns #DEBUG.
		*/
		static const Level& toLevel(const tstring& sArg);

		/**
		Convert an integer passed as argument to a level. If the
		conversion fails, then this method returns #DEBUG.

		*/
		static const Level& toLevel(int val);

		/**
		Convert an integer passed as argument to a level. If the
		conversion fails, then this method returns the specified default.
		*/
		static const Level& toLevel(int val, const Level& defaultLevel);


		/**
		Convert the string passed as argument to a level. If the
		conversion fails, then this method returns the value of
		<code>defaultLevel</code>.
		*/
		static const Level& toLevel(const tstring& sArg, const Level& defaultLevel);



        enum
        {
            OFF_INT = INT_MAX,
            FATAL_INT = 50000,
            ERROR_INT = 40000,
            WARN_INT = 30000,
            INFO_INT = 20000,
            DEBUG_INT = 10000,
            ALL_INT = INT_MIN
        };

		/**
		The <code>ALL</code> level designates all the levels
		*/
		static const Level ALL;

		/**
		The <code>FATAL</code> level designates very severe error
		events that will presumably lead the application to abort.
		*/
		static const Level FATAL;

		/**
		The <code>ERROR</code> level designates error events that
		might still allow the application to continue running.  */
		static const Level ERROR;

		/**
		The <code>WARN</code> level designates potentially harmful situations.
		*/
		static const Level WARN;

		/**
		The <code>INFO</code> level designates informational messages
		that highlight the progress of the application at coarse-grained
		level.  */
		static const Level INFO;

		/**
		The <code>DEBUG</code> level designates fine-grained
		informational events that are most useful to debug an
		application.  */
		static const Level DEBUG;
	
		/**
		The <code>OFF</code> level designates not set level
		*/
		static const Level OFF;

		static const Level& getAllLevel();
		static const Level& getFatalLevel();
		static const Level& getErrorLevel();
		static const Level& getWarnLevel();
		static const Level& getInfoLevel();
		static const Level& getDebugLevel();
		static const Level& getOffLevel();

		/**
		Two levels are equal if their level fields are equal.
		*/
		virtual bool equals(const Level& level) const;

		/**
		Return the syslog equivalent of this level as an integer.
		*/
		virtual int getSyslogEquivalent() const;


		/**
		Returns <code>true</code> if this level has a higher or equal
		level than the level passed as argument, <code>false</code>
		otherwise.

		<p>You should think twice before overriding the default
		implementation of <code>isGreaterOrEqual</code> method.

		*/
		virtual bool isGreaterOrEqual(const Level& level) const;

		/**
		Returns the string representation of this priority.
		*/
		virtual const tstring& toString() const;

		/**
		Returns the integer representation of this level.
		*/
		virtual int toInt() const;

	public:
		int level;
		tstring levelStr;
		int syslogEquivalent;
	};
};

#endif //_LOG4CXX_LEVEL_H
