/***************************************************************************
                          formattinginfo.h  -  class FormattingInfo
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

#ifndef _LOG4CXX_HELPER_FORMATTING_INFO_H
#define _LOG4CXX_HELPER_FORMATTING_INFO_H

namespace log4cxx
{
	namespace helpers
	{
		/**
		FormattingInfo instances contain the information obtained when parsing
		formatting modifiers in conversion modifiers.
		*/
		class FormattingInfo 
		{
		public:

			int min;
			int max;
			bool leftAlign;

			FormattingInfo();
			void reset();
			void dump();

		}; // class FormattingInfo
	}; // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPER_FORMATTING_INFO_H
