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
#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/helpers/objectptr.h>

#ifndef _LOG4CXX_LEVEL_H
#define _LOG4CXX_LEVEL_H

#undef ERROR

namespace log4cxx
{
    class Level;
	/** smart pointer to a Level instance */
    typedef helpers::ObjectPtrT<Level> LevelPtr;

	/**
	Defines the minimum set of levels recognized by the system, that is
	<code>OFF</code>, <code>FATAL</code>, <code>ERROR</code>,
	<code>WARN</code>, <code>INFO</code, <code>DEBUG</code> and
	<code>ALL</code>.
	<p>The <code>Level</code> class may be subclassed to define a larger
	level set.
	*/
	class LOG4CXX_EXPORT Level : public helpers::ObjectImpl
	{
	public:
		class LOG4CXX_EXPORT LevelClass : public helpers::Class
		{
		protected:
			LevelClass(const String& className) : helpers::Class(className) {}

		public:
			LevelClass() : helpers::Class(_T("Level")) {}

			virtual const LevelPtr& toLevel(const String& sArg)
			{ return Level::toLevel(sArg); }
			
			virtual const LevelPtr& toLevel(int val)
			{ return Level::toLevel(val); }
		};

		DECLARE_LOG4CXX_OBJECT_WITH_CUSTOM_CLASS(Level, LevelClass)
		BEGIN_LOG4CXX_CAST_MAP()
			LOG4CXX_CAST_ENTRY(Level)
		END_LOG4CXX_CAST_MAP()

		/**
		Instantiate a Level object.
		*/
		Level(int level, const String& levelStr, int syslogEquivalent);

		/**
		Convert the string passed as argument to a level. If the
		conversion fails, then this method returns #DEBUG.
		*/
		static const LevelPtr& toLevel(const String& sArg);

		/**
		Convert an integer passed as argument to a level. If the
		conversion fails, then this method returns #DEBUG.
		*/
		static const LevelPtr& toLevel(int val);

		/**
		Convert an integer passed as argument to a level. If the
		conversion fails, then this method returns the specified default.
		*/
		static const LevelPtr& toLevel(int val, const LevelPtr& defaultLevel);

		/**
		Convert the string passed as argument to a level. If the
		conversion fails, then this method returns the value of
		<code>defaultLevel</code>.
		*/
		static const LevelPtr& toLevel(const String& sArg,
			const LevelPtr& defaultLevel);

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

#if !defined(WIN32) || defined(LOG4CXX)
		/**
		The <code>ALL</code> level designates all the levels
		*/
		static const LevelPtr ALL;

		/**
		The <code>FATAL</code> level designates very severe error
		events that will presumably lead the application to abort.
		*/
		static const LevelPtr FATAL;

		/**
		The <code>ERROR</code> level designates error events that
		might still allow the application to continue running.  */
		static const LevelPtr ERROR;

		/**
		The <code>WARN</code> level designates potentially harmful situations.
		*/
		static const LevelPtr WARN;

		/**
		The <code>INFO</code> level designates informational messages
		that highlight the progress of the application at coarse-grained
		level.  */
		static const LevelPtr INFO;

		/**
		The <code>DEBUG</code> level designates fine-grained
		informational events that are most useful to debug an
		application.  */
		static const LevelPtr DEBUG;
	
		/**
		The <code>OFF</code> level designates not set level
		*/
		static const LevelPtr OFF;
#endif

		static const LevelPtr& getAllLevel();
		static const LevelPtr& getFatalLevel();
		static const LevelPtr& getErrorLevel();
		static const LevelPtr& getWarnLevel();
		static const LevelPtr& getInfoLevel();
		static const LevelPtr& getDebugLevel();
		static const LevelPtr& getOffLevel();

		/**
		Two levels are equal if their level fields are equal.
		*/
		virtual bool equals(const LevelPtr& level) const;

		inline bool operator==(const Level& level) const
			{ return (this->level == level.level); }

		inline bool operator!=(const Level& level) const
			{ return (this->level != level.level); }

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
		virtual bool isGreaterOrEqual(const LevelPtr& level) const;

		/**
		Returns the string representation of this priority.
		*/
		virtual const String& toString() const;

		/**
		Returns the integer representation of this level.
		*/
		virtual int toInt() const;

	public:
		int level;
		String levelStr;
		int syslogEquivalent;
	};
};

#define DECLARE_LOG4CXX_LEVEL(level)\
public:\
	class Class##level : public Level::LevelClass\
{\
public:\
	Class##level() : Level::LevelClass(_T(#level)) {}\
	virtual const LevelPtr& toLevel(const String& sArg)\
	{ return level::toLevel(sArg); }\
	virtual const LevelPtr& toLevel(const int val)\
	{ return level::toLevel(val); }\
};\
DECLARE_LOG4CXX_OBJECT_WITH_CUSTOM_CLASS(level, Class##level)
	
#define IMPLEMENT_LOG4CXX_LEVEL(level) \
IMPLEMENT_LOG4CXX_OBJECT_WITH_CUSTOM_CLASS(level, Class##level)



#endif //_LOG4CXX_LEVEL_H
