/***************************************************************************
                          xml.h  -  XML helpers
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

#ifndef _LOG4CXX_HELPERS_XML_H
#define _LOG4CXX_HELPERS_XML_H

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/object.h>
#include <log4cxx/helpers/exception.h>

namespace log4cxx
{
	namespace helpers
	{
		class XMLDOMNode;
		typedef helpers::ObjectPtrT<XMLDOMNode> XMLDOMNodePtr;

		class XMLDOMDocument;
		typedef helpers::ObjectPtrT<XMLDOMDocument> XMLDOMDocumentPtr;

		class XMLDOMElement;
		typedef helpers::ObjectPtrT<XMLDOMElement> XMLDOMElementPtr;

		class XMLDOMNodeList;
		typedef helpers::ObjectPtrT<XMLDOMNodeList> XMLDOMNodeListPtr;

		class DOMException : public RuntimeException
		{
		};

		class XMLDOMNode : virtual public Object
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(XMLDOMNode)
			enum XMLDOMNodeType
			{
				NOT_IMPLEMENTED_NODE = 0,
				ELEMENT_NODE = 1,
				DOCUMENT_NODE = 9,
			};
			
			virtual XMLDOMNodeListPtr getChildNodes() = 0;
			virtual XMLDOMNodeType getNodeType() = 0;
			virtual XMLDOMDocumentPtr getOwnerDocument() = 0;
		};

		class XMLDOMDocument : virtual public XMLDOMNode
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(XMLDOMDocument)
			virtual void load(const tstring& fileName) = 0;
			virtual XMLDOMElementPtr getDocumentElement() = 0;
			virtual XMLDOMElementPtr getElementById(const tstring& tagName, const tstring& elementId) = 0;
		};

		class XMLDOMElement : virtual public XMLDOMNode
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(XMLDOMElement)
			virtual tstring getTagName() = 0;
			virtual tstring getAttribute(const tstring& name) = 0;
		};

		class XMLDOMNodeList : virtual public Object
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(XMLDOMNodeList)
			virtual int getLength() = 0;
			virtual XMLDOMNodePtr item(int index) = 0;
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPERS_XML_H

