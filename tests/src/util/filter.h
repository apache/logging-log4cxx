/***************************************************************************
                                filter.h
                             -------------------
    begin                : 2003/12/11
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

#ifndef _LOG4CXX_TESTS_UTIL_FILTER_H
#define _LOG4CXX_TESTS_UTIL_FILTER_H

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/exception.h>

#define BASIC_PAT "\\[\\d*\\] (FATAL|ERROR|WARN|INFO|DEBUG)"
#define ISO8601_PAT "^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2},\\d{3}"
#define ABSOLUTE_DATE_AND_TIME_PAT \
	"^\\d{1,2} .{2,6}\\.? 200\\d \\d{2}:\\d{2}:\\d{2},\\d{3}"
#define ABSOLUTE_TIME_PAT "^\\d{2}:\\d{2}:\\d{2},\\d{3}"
#define RELATIVE_TIME_PAT "^\\d{1,10}"

namespace log4cxx
{
	class UnexpectedFormatException : public helpers::Exception
	{
	public:
		UnexpectedFormatException(const String& message)
		: message(message) {}

		virtual String getMessage()
			{ return message; }

	protected:
		String message;
	};

	class Filter
	{
	public:
		virtual String filter(const String& in)
			const throw(UnexpectedFormatException) = 0;
	};
};

#endif //_LOG4CXX_TESTS_UTIL_FILTER_H
