/***************************************************************************
                          gnomexmlreader.cpp  -  GnomeXMLReader
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

#include <log4cxx/config.h>

#ifdef HAVE_LIBXML2

#include <log4cxx/helpers/gnomexmlreader.h>
#include <log4cxx/helpers/loglog.h>

using namespace log4cxx;
using namespace log4cxx::xml;
using namespace log4cxx::helpers;

void GnomeXMLReader::parse(xml::DOMConfigurator * configurator,
	const tstring& URL)
{
	this->configurator = configurator;

	USES_CONVERSION;
	xmlDocPtr document = xmlParseFile(T2A(URL.c_str()));

	if (document != 0)
	{
		parseElement(tstring(),xmlDocGetRootElement(document));
 	}
	else
	{
		LogLog::error(_T("Could not open [")+URL+_T("]."));
	}

	xmlFree(document);
}

void GnomeXMLReader::parseElement(const tstring& parentTagName,
	xmlNodePtr element)
{
	USES_CONVERSION;
	tstring tagName = A2T((char *)element->name);
	configurator->BuildElement(parentTagName, tagName);

	// parse attributes
	xmlAttrPtr attribute = element->properties;

	while (attribute != 0)
	{
		tstring name = A2T((char *)attribute->name);
		tstring value = A2T((char *)xmlNodeListGetString(
			attribute->doc, attribute->children, 1));
		
		//tcout << _T("BuildAttribute parentTagName=") << parentTagName
		//	<< _T(", tagName=") << tagName
		//	<< _T(", name=") << name
		//	<< _T(", value=") << value << std::endl;
		configurator->BuildAttribute(tagName, name, value);
 		attribute = attribute->next;
	}

	// parse children elements
	xmlNodePtr child = element->xmlChildrenNode;

	while (child != 0)
	{
		if (child->type == XML_ELEMENT_NODE)
		{
			parseElement(tagName, child);
		}
		child = child->next;
	}
}

#endif // HAVE_LIBXML2
