/***************************************************************************
                          msxmlreader.h  -  MsXMLReader
                             -------------------
    begin                : dim avr 20 2003
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

#ifndef _LOG4CXX_HELPERS_MS_XML_READER_H
#define _LOG4CXX_HELPERS_MS_XML_READER_H

#ifdef WIN32

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/xml/domconfigurator.h>

#ifndef __IXMLDOMDocument_FWD_DEFINED__
#import "msxml.dll"
#endif

namespace log4cxx
{
	namespace helpers
	{
		class MsXMLReader
		{
		public:
			void parse(xml::DOMConfigurator * configurator, const tstring& URL);

		protected:
			void CreateDOMDocumentInstance();
			void parseElement(const tstring& parentTagName, MSXML::IXMLDOMElementPtr& element);

			MSXML::IXMLDOMDocumentPtr document;
			xml::DOMConfigurator * configurator;
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif // WIN32

#endif // _LOG4CXX_HELPERS_MS_XML_READER_H
