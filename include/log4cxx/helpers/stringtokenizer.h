/***************************************************************************
                          stringtokenizer.h  -  class StringTokenizer
                             -------------------
    begin                : 2003/08/02
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
#ifndef _LOG4CXX_HELPERS_STRING_TOKENIZER_H
#define _LOG4CXX_HELPERS_STRING_TOKENIZER_H

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/exception.h>

namespace log4cxx
{
	namespace helpers
	{
		class NoSuchElementException : public Exception
		{
		public:
			tstring getMessage() { return tstring(); }
		};

		class StringTokenizer
		{
		public:
			StringTokenizer(const tstring& str, const tstring& delim);
			~StringTokenizer();
			bool hasMoreTokens();
			tstring nextToken();

		protected:
			TCHAR * str;
			tstring delim;
			TCHAR * token;
			TCHAR * state;
		}; // class StringTokenizer
	}; // namespace helpers;
}; // namespace log4cxx;

#endif //_LOG4CXX_HELPERS_STRING_TOKENIZER_H
