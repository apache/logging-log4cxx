/***************************************************************************
                          msxml.h  -  XML helpers
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

#ifndef _LOG4CXX_HELPERS_MSXML_H
#define _LOG4CXX_HELPERS_MSXML_H

#include <log4cxx/config.h>

#ifdef HAVE_MS_XML

#include <log4cxx/helpers/xml.h>
#include <log4cxx/helpers/objectimpl.h>

//#ifndef __IXMLDOMDocument_FWD_DEFINED__
#import "msxml.dll"
//#endif

namespace log4cxx
{
	namespace helpers
	{
		class LOG4CXX_EXPORT MsXMLDOMNode : 
			virtual public XMLDOMNode,
			virtual public ObjectImpl
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(MsXMLDOMNode)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(XMLDOMNode)
			END_LOG4CXX_CAST_MAP()

			MsXMLDOMNode(MSXML::IXMLDOMNodePtr node);

			virtual XMLDOMNodeListPtr getChildNodes();
			virtual XMLDOMNodeType getNodeType()
				{ return NOT_IMPLEMENTED_NODE; }

			virtual XMLDOMDocumentPtr getOwnerDocument();

		protected:
			MSXML::IXMLDOMNodePtr node;
		};

		class LOG4CXX_EXPORT MsXMLDOMDocument : 
			virtual public XMLDOMDocument,
			virtual public ObjectImpl
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(MsXMLDOMDocument)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(XMLDOMDocument)
				LOG4CXX_CAST_ENTRY(XMLDOMNode)
			END_LOG4CXX_CAST_MAP()

			MsXMLDOMDocument();
			MsXMLDOMDocument(MSXML::IXMLDOMDocumentPtr document);
			~MsXMLDOMDocument();

			virtual XMLDOMNodeListPtr getChildNodes();
			virtual XMLDOMNodeType getNodeType()
				{ return XMLDOMNode::DOCUMENT_NODE; }
			virtual XMLDOMDocumentPtr getOwnerDocument();
			virtual void load(const String& fileName);
			virtual XMLDOMElementPtr getDocumentElement();
			virtual XMLDOMElementPtr getElementById(const String& tagName, const String& elementId);

		protected:
			MSXML::IXMLDOMDocumentPtr document;
			bool mustCallCoUninitialize;
		};

		class LOG4CXX_EXPORT MsXMLDOMElement : 
			virtual public XMLDOMElement,
			virtual public ObjectImpl
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(MsXMLDOMElement)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(XMLDOMElement)
				LOG4CXX_CAST_ENTRY(XMLDOMNode)
			END_LOG4CXX_CAST_MAP()

			MsXMLDOMElement(MSXML::IXMLDOMElementPtr element);

			virtual XMLDOMNodeListPtr getChildNodes();
			virtual XMLDOMNodeType getNodeType()
				{ return XMLDOMNode::ELEMENT_NODE; }
			virtual XMLDOMDocumentPtr getOwnerDocument();
			virtual String getTagName();
			virtual String getAttribute(const String& name);

		protected:
			MSXML::IXMLDOMElementPtr element;
		};

		class LOG4CXX_EXPORT MsXMLDOMNodeList : 
			virtual public XMLDOMNodeList,
			virtual public ObjectImpl
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(MsXMLDOMNodeList)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(XMLDOMNodeList)
			END_LOG4CXX_CAST_MAP()

			MsXMLDOMNodeList(MSXML::IXMLDOMNodeListPtr nodeList);

			virtual int getLength();
			virtual XMLDOMNodePtr item(int index);

		protected:
			MSXML::IXMLDOMNodeListPtr nodeList;
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif // HAVE_MS_XML
#endif // _LOG4CXX_HELPERS_MSXML_H
