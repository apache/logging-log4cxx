/***************************************************************************
                          gnomexmlreader.h  -  GnomeXMLReader
                             -------------------
    begin                : mer mai 7 2003
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

#ifdef HAVE_LIBXML

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/xml/domconfigurator.h>
#include <libxml/tree.h>

namespace log4cxx
{
	namespace helpers
	{
		class GnomeXMLReader
		{
		public:
			void parse(xml::DOMConfigurator * configurator, const tstring& URL);

		protected:
			void parseElement(const tstring& parentTagName,
				xmlNodePtr element);

			xml::DOMConfigurator * configurator;
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif // HAVE_LIBXML

#endif // _LOG4CXX_HELPERS_MS_XML_READER_H
