/***************************************************************************
                          optionconverter.h  -  class OptionConverter
                             -------------------
    begin                : mer avr 30 2003
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

#ifndef _LOG4CXX_HELPER_OPTION_CONVERTER_H
#define _LOG4CXX_HELPER_OPTION_CONVERTER_H

#include <log4cxx/helpers/tchar.h>

namespace log4cxx
{
	namespace helpers
	{
		class OptionConverter
		{
			static tstring DELIM_START;
			static TCHAR DELIM_STOP;
			static int DELIM_START_LEN;
			static int DELIM_STOP_LEN;

		/** OptionConverter is a static class. */
		private:
			OptionConverter() {}

		public:
			static bool toBoolean(const tstring& value, bool dEfault);
			static int toInt(const tstring& value, int dEfault);
			static long toFileSize(const tstring& value, long dEfault);
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif //_LOG4CXX_HELPER_OPTION_CONVERTER_H

