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

#ifndef __IXMLDOMDocument_FWD_DEFINED__
#import "msxml.dll"
#endif

namespace log4cxx
{
	namespace helpers
	{
		class MsXMLDOMNode : 
			virtual public XMLDOMNode,
			virtual public ObjectImpl
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(MsXMLDOMNode)
			BEGIN_LOG4CXX_INTERFACE_MAP()
				LOG4CXX_INTERFACE_ENTRY(XMLDOMNode)
			END_LOG4CXX_INTERFACE_MAP()

			MsXMLDOMNode(MSXML::IXMLDOMNodePtr node);

			virtual XMLDOMNodeListPtr getChildNodes();
			virtual XMLDOMNodeType getNodeType()
				{ return NOT_IMPLEMENTED_NODE; }

			virtual XMLDOMDocumentPtr getOwnerDocument();

		protected:
			MSXML::IXMLDOMNodePtr node;
		};

		class MsXMLDOMDocument : 
			virtual public XMLDOMDocument,
			virtual public ObjectImpl
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(MsXMLDOMDocument)
			BEGIN_LOG4CXX_INTERFACE_MAP()
				LOG4CXX_INTERFACE_ENTRY(XMLDOMDocument)
				LOG4CXX_INTERFACE_ENTRY(XMLDOMNode)
			END_LOG4CXX_INTERFACE_MAP()

			MsXMLDOMDocument();
			MsXMLDOMDocument(MSXML::IXMLDOMDocumentPtr document);

			virtual XMLDOMNodeListPtr getChildNodes();
			virtual XMLDOMNodeType getNodeType()
				{ return XMLDOMNode::DOCUMENT_NODE; }
			virtual XMLDOMDocumentPtr getOwnerDocument();
			virtual void load(const tstring& fileName);
			virtual XMLDOMElementPtr getDocumentElement();
			virtual XMLDOMElementPtr getElementById(const tstring& tagName, const tstring& elementId);

		protected:
			MSXML::IXMLDOMDocumentPtr document;
		};

		class MsXMLDOMElement : 
			virtual public XMLDOMElement,
			virtual public ObjectImpl
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(MsXMLDOMElement)
			BEGIN_LOG4CXX_INTERFACE_MAP()
				LOG4CXX_INTERFACE_ENTRY(XMLDOMElement)
				LOG4CXX_INTERFACE_ENTRY(XMLDOMNode)
			END_LOG4CXX_INTERFACE_MAP()

			MsXMLDOMElement(MSXML::IXMLDOMElementPtr element);

			virtual XMLDOMNodeListPtr getChildNodes();
			virtual XMLDOMNodeType getNodeType()
				{ return XMLDOMNode::ELEMENT_NODE; }
			virtual XMLDOMDocumentPtr getOwnerDocument();
			virtual tstring getTagName();
			virtual tstring getAttribute(const tstring& name);

		protected:
			MSXML::IXMLDOMElementPtr element;
		};

		class MsXMLDOMNodeList : 
			virtual public XMLDOMNodeList,
			virtual public ObjectImpl
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(MsXMLDOMNodeList)
			BEGIN_LOG4CXX_INTERFACE_MAP()
				LOG4CXX_INTERFACE_ENTRY(XMLDOMNodeList)
			END_LOG4CXX_INTERFACE_MAP()

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
