/***************************************************************************
                                 xlevel.h
                             -------------------
    begin                : 2003/12/02
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/
 /***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the license.apl file.                                   *
 ***************************************************************************/

#include <log4cxx/level.h>

namespace log4cxx
{
	class XLevel : public Level
	{
		DECLARE_LOG4CXX_LEVEL(XLevel)

	public:
        enum
        {
            TRACE_INT = Level::DEBUG_INT - 1,
			LETHAL_INT = Level::FATAL_INT + 1
        };

		static const LevelPtr TRACE;
		static const LevelPtr LETHAL;

		XLevel(int level, const String& levelStr, int syslogEquivalent);
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
	};
};
