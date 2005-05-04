/*
 * Copyright 2003-2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _LOG4CXX_HELPERS_MSXML_H
#define _LOG4CXX_HELPERS_MSXML_H

#ifdef _WIN32

#include <log4cxx/helpers/xml.h>
#include <log4cxx/helpers/objectimpl.h>

//#ifndef __IXMLDOMDocument_FWD_DEFINED__
#import "msxml.dll"
//#endif

namespace log4cxx
{
        class File;
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
                        virtual void load(const File& fileName);
                        virtual XMLDOMElementPtr getDocumentElement();
                        virtual XMLDOMElementPtr getElementById(const LogString& tagName, const LogString& elementId);

                        static LogString decode(BSTR str);
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
                        virtual LogString getTagName();
                        virtual LogString getAttribute(const LogString& name);

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
        }  // namespace helpers
} // namespace log4cxx

#endif // LOG4CXX_HAVE_MS_XML
#endif // _LOG4CXX_HELPERS_MSXML_H
