/***************************************************************************
                          stringhelper.h  -  description
                             -------------------
    begin                : mar avr 15 2003
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

#ifndef _LOG4CXX_HELPERS_STRING_HELPER_H
#define _LOG4CXX_HELPERS_STRING_HELPER_H
 
#include <log4cxx/config.h>
#include <log4cxx/helpers/tchar.h>
#include <algorithm>

namespace log4cxx
{
    namespace helpers
    {
        class StringHelper
        {

            public:
            static tstring toUpperCase(const tstring& s)
            {
				tstring d;
                std::transform(s.begin(), s.end(),
					std::insert_iterator<tstring>(d, d.begin()), totupper);
				return d;
            }

            static tstring toLowerCase(const tstring& s)
            {
				tstring d;
                std::transform(s.begin(), s.end(),
					std::insert_iterator<tstring>(d, d.begin()), totlower);
				return d;
            }

            static tstring trim(const tstring& s)
            {
				tstring::size_type pos = s.find_first_not_of(_T(' '));
				if (pos == tstring::npos)
				{
					return tstring();
				}

				tstring::size_type n = s.find_last_not_of(_T(' ')) - pos + 1;
				return s.substr(pos, n);
            }

            static bool equalsIgnoreCase(const tstring& s1, const tstring& s2)
            {
				return toLowerCase(s1) == toLowerCase(s2);
            }
        };
    };
};

#endif //_LOG4CXX_HELPERS_STRING_HELPER_H
