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

#ifndef _LOG4CXX_HELPERS_GNOMEXML_H
#define _LOG4CXX_HELPERS_GNOMEXML_H

#include <log4cxx/log4cxx.h>

#if !defined(_WIN32)

#include <log4cxx/helpers/xml.h>
#include <log4cxx/helpers/objectimpl.h>

#include <libxml/tree.h>

//
//  This checks that tree.h is from libxml2 not libxml
//  The name of this class might tempt you to put /usr/include/gnome-xml
//      in the include path which, at least for my distribution, is libxml.
//      libxml2 is located in /usr/include/libxml2.  Note: gnomexml.cpp
//      can compile for both libxml and libxml2 if ".children" is
//      replaced by ".xmlChildrenNode" and "#include <libxml/parse.h>" is
//      added.  See bug report LOGCXX-21.
//
#if LIBXML_VERSION < 20000
#error libxml include file found where libxml2 was expected
#endif

namespace log4cxx
{
        class File;
        namespace helpers
        {
                class GnomeXMLDOMNode :
                        virtual public XMLDOMNode,
                        virtual public ObjectImpl
                {
                public:
                        DECLARE_ABSTRACT_LOG4CXX_OBJECT(GnomeXMLDOMNode)
                        BEGIN_LOG4CXX_CAST_MAP()
                                LOG4CXX_CAST_ENTRY(XMLDOMNode)
                        END_LOG4CXX_CAST_MAP()

                        GnomeXMLDOMNode(xmlNodePtr node);

                        virtual XMLDOMNodeListPtr getChildNodes();
                        virtual XMLDOMNodeType getNodeType()
                                { return NOT_IMPLEMENTED_NODE; }

                        virtual XMLDOMDocumentPtr getOwnerDocument();

                protected:
                        xmlNodePtr node;

                private:
                        //   prevent assignment or copy statements
                        GnomeXMLDOMNode(const GnomeXMLDOMNode&);
                        GnomeXMLDOMNode& operator=(const GnomeXMLDOMNode&);
                };

                class GnomeXMLDOMDocument :
                        virtual public XMLDOMDocument,
                        virtual public ObjectImpl
                {
                public:
                        DECLARE_ABSTRACT_LOG4CXX_OBJECT(GnomeXMLDOMDocument)
                        BEGIN_LOG4CXX_CAST_MAP()
                                LOG4CXX_CAST_ENTRY(XMLDOMDocument)
                                LOG4CXX_CAST_ENTRY(XMLDOMNode)
                        END_LOG4CXX_CAST_MAP()

                        GnomeXMLDOMDocument();
                        GnomeXMLDOMDocument(xmlDocPtr document);
                        ~GnomeXMLDOMDocument();

                        virtual XMLDOMNodeListPtr getChildNodes();
                        virtual XMLDOMNodeType getNodeType()
                                { return XMLDOMNode::DOCUMENT_NODE; }
                        virtual XMLDOMDocumentPtr getOwnerDocument();
                        virtual void load(const File& fileName);
                        virtual XMLDOMElementPtr getDocumentElement();
                        virtual XMLDOMElementPtr getElementById(
                                const LogString& tagName, const LogString& elementId);

                protected:
                        xmlDocPtr document;
                        bool ownDocument;

                private:
                        //   prevent assignment or copy statements
                       GnomeXMLDOMDocument(const GnomeXMLDOMDocument&);
                       GnomeXMLDOMDocument& operator=(const GnomeXMLDOMDocument&);
                };

                class GnomeXMLDOMElement :
                        virtual public XMLDOMElement,
                        virtual public ObjectImpl
                {
                public:
                        DECLARE_ABSTRACT_LOG4CXX_OBJECT(GnomeXMLDOMElement)
                        BEGIN_LOG4CXX_CAST_MAP()
                                LOG4CXX_CAST_ENTRY(XMLDOMElement)
                                LOG4CXX_CAST_ENTRY(XMLDOMNode)
                        END_LOG4CXX_CAST_MAP()

                        GnomeXMLDOMElement(xmlNodePtr element);

                        virtual XMLDOMNodeListPtr getChildNodes();
                        virtual XMLDOMNodeType getNodeType()
                                { return XMLDOMNode::ELEMENT_NODE; }
                        virtual XMLDOMDocumentPtr getOwnerDocument();
                        virtual LogString getTagName();
                        virtual LogString getAttribute(const LogString& name);

                protected:
                        xmlNodePtr element;
                private:
                        //   prevent assignment or copy statements
                       GnomeXMLDOMElement(const GnomeXMLDOMElement&);
                       GnomeXMLDOMElement& operator=(const GnomeXMLDOMElement&);
                };

                class GnomeXMLDOMNodeList :
                        virtual public XMLDOMNodeList,
                        virtual public ObjectImpl
                {
                public:
                        DECLARE_ABSTRACT_LOG4CXX_OBJECT(GnomeXMLDOMNodeList)
                        BEGIN_LOG4CXX_CAST_MAP()
                                LOG4CXX_CAST_ENTRY(XMLDOMNodeList)
                        END_LOG4CXX_CAST_MAP()

                        GnomeXMLDOMNodeList(xmlNodePtr firstChild);

                        virtual int getLength();
                        virtual XMLDOMNodePtr item(int index);

                protected:
                        xmlNodePtr firstChild;
                        xmlNodePtr currentChild;
                        int currentIndex;

                private:
                        //   prevent assignment or copy statements
                       GnomeXMLDOMNodeList(const GnomeXMLDOMNodeList&);
                       GnomeXMLDOMNodeList& operator=(const GnomeXMLDOMNodeList&);
                };
        }  // namespace helpers
} // namespace log4cxx

#endif // LOG4CXX_HAVE_LIBXML2
#endif // _LOG4CXX_HELPERS_MSXML_H
