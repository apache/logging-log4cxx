/***************************************************************************
                          transform.h  -  class Transform
                             -------------------
    begin                : sam mai 17 2003
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

#ifndef _LOG4CXX_HELPERS_TRANSFORM_H
#define _LOG4CXX_HELPERS_TRANSFORM_H

#include <log4cxx/helpers/tchar.h>

namespace log4cxx
{
	namespace helpers
	{
		/**
		Utility class for transforming strings.
		*/
		class Transform
		{
		private:
			static tstring CDATA_START;
			static tstring CDATA_END;
			static tstring CDATA_PSEUDO_END;
			static tstring CDATA_EMBEDED_END;
			static int CDATA_END_LEN;

		public:
			/**
			* This method takes a string which may contain HTML tags (ie,
			* &lt;b&gt;, &lt;table&gt;, etc) and replaces any '<' and '>'
			* characters with respective predefined entity references.
			*
			* @param buf output stream where to write the modified string.
			* @param input The text to be converted.
			* @return The input string with the characters '<' and '>' replaced with
			*  &amp;lt; and &amp;gt; respectively.
			* */
			static void appendEscapingTags(
				tostream& buf, const tstring& input);

			/**
			* Ensures that embeded CDEnd strings (]]>) are handled properly
			* within message, NDC and throwable tag text.
			*
			* @param buf output stream holding the XML data to this point.  The
			* initial CDStart (<![CDATA[) and final CDEnd (]]>) of the CDATA
			* section are the responsibility of the calling method.
			* @param input The String that is inserted into an existing CDATA
			* Section within buf.
			*/
			static void appendEscapingCDATA(
				tostream& buf, const tstring& input);
		}; // class Transform
	}; // namespace helpers
}; //namespace log4cxx

#endif // _LOG4CXX_HELPERS_TRANSFORM_H
