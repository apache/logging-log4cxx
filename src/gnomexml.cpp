/*
 * Copyright 2003,2004 The Apache Software Foundation.
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


#if !defined(_WIN32)

#include <log4cxx/helpers/gnomexml.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/file.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(GnomeXMLDOMDocument)
IMPLEMENT_LOG4CXX_OBJECT(GnomeXMLDOMNodeList)
IMPLEMENT_LOG4CXX_OBJECT(GnomeXMLDOMNode)
IMPLEMENT_LOG4CXX_OBJECT(GnomeXMLDOMElement)

// GnomeXMLDOMNode

GnomeXMLDOMNode::GnomeXMLDOMNode(xmlNodePtr node)
: node(node)
{
}

XMLDOMNodeListPtr GnomeXMLDOMNode::getChildNodes()
{
        if (node == 0) throw DOMException();
        return new GnomeXMLDOMNodeList(node->children);
}

XMLDOMDocumentPtr GnomeXMLDOMNode::getOwnerDocument()
{
        if (node == 0) throw DOMException();
        return new GnomeXMLDOMDocument(node->doc);
}

// GnomeXMLDOMDocument

GnomeXMLDOMDocument::GnomeXMLDOMDocument(xmlDocPtr document)
: document(document), ownDocument(false)
{
}

GnomeXMLDOMDocument::GnomeXMLDOMDocument()
: document(0), ownDocument(false)
{
}

GnomeXMLDOMDocument::~GnomeXMLDOMDocument()
{
        if (ownDocument)
        {
                ::xmlFreeDoc(document);
        }
}

XMLDOMNodeListPtr GnomeXMLDOMDocument::getChildNodes()
{
        if (document == 0) throw DOMException();
        return new GnomeXMLDOMNodeList(::xmlDocGetRootElement(document));
}

XMLDOMDocumentPtr GnomeXMLDOMDocument::getOwnerDocument()
{
        return this;
}

void GnomeXMLDOMDocument::load(const File& fileName)
{
        if (document != 0)
        {
                if (ownDocument)
                {
                        ::xmlFreeDoc(document);
                }
                document = 0;
        }

        std::string fn;
        Transcoder::encode(fileName.getName(), fn);
        document = ::xmlParseFile(fn.c_str());

        if (document == 0)
        {
                LogLog::error(LogString(LOG4CXX_STR("Could not open [")) +
                   fileName.getName() + LOG4CXX_STR("]."));
        }
        else
        {
                ownDocument = true;
        }
}

XMLDOMElementPtr GnomeXMLDOMDocument::getDocumentElement()
{
        if (document == 0) throw DOMException();
        xmlNodePtr element = ::xmlDocGetRootElement(document);
        return new GnomeXMLDOMElement(element);
}

XMLDOMElementPtr GnomeXMLDOMDocument::getElementById(const LogString& tagName,
   const LogString& elementId)
{
        if (document == 0) throw DOMException();
        xmlNodePtr node = ::xmlDocGetRootElement(document);

        std::string elemId;
        Transcoder::encode(elementId, elemId);

        std::string tag;
        Transcoder::encode(tagName, tag);

        while (node != 0)
        {
                if (node->type == XML_ELEMENT_NODE
                        && tag == (const char*) node->name)
                {
                        char * attributeValue = (char *)xmlGetProp(
                                node, (const xmlChar *)"name");
                        if (attributeValue != 0
                                && elemId == attributeValue)
                        {
                                return new GnomeXMLDOMElement(node);
                        }
                }

                if (node->children != 0)
                {
                        node = node->children;
                }
                else if (node->next != 0)
                {
                        node = node->next;
                }
                else
                {
                        node = node->parent->next;
                }
        }

        return 0;
}

// GnomeXMLDOMElement
GnomeXMLDOMElement::GnomeXMLDOMElement(xmlNodePtr element)
: element(element)
{
}

XMLDOMNodeListPtr GnomeXMLDOMElement::getChildNodes()
{
        if (element == 0) throw DOMException();
        return new GnomeXMLDOMNodeList(element->children);
}

XMLDOMDocumentPtr GnomeXMLDOMElement::getOwnerDocument()
{
        if (element == 0) throw DOMException();
        return new GnomeXMLDOMDocument(element->doc);
}

LogString GnomeXMLDOMElement::getTagName()
{
        if (element == 0) throw DOMException();
        LogString tagname;
        Transcoder::decode((const char*) element->name, tagname);
        return tagname;
}

LogString GnomeXMLDOMElement::getAttribute(const LogString& name)
{
        if (element == 0) throw DOMException();
        std::string nm;
        Transcoder::encode(name, nm);
        char * attributeValue = (char *)xmlGetProp(
                element, (const xmlChar*) nm.c_str());
        LogString retval;
        if (attributeValue != 0) {
           Transcoder::decode((const char*) attributeValue, retval);
        }
        return retval;
}

// GnomeXMLDOMNodeList
GnomeXMLDOMNodeList::GnomeXMLDOMNodeList(xmlNodePtr firstChild)
: firstChild(firstChild), currentChild(firstChild), currentIndex(0)
{
}

int GnomeXMLDOMNodeList::getLength()
{
        xmlNodePtr child = firstChild;
        int length = 0;
        while (child != 0)
        {
                child = child->next;
                length++;
        }

        return length;
}

XMLDOMNodePtr GnomeXMLDOMNodeList::item(int index)
{
        xmlNodePtr child = 0;

        if (index == currentIndex)
        {
                child = currentChild;
        }
        else
        {
                child = firstChild;
                int n = 0;
                while (child != 0 && n < index)
                {
                        child = child->next;
                        n++;
                }
        }

        currentIndex = index + 1;
        currentChild = child ? child->next : 0;

        if (child != 0)
        {
                if (child->type == XML_ELEMENT_NODE)
                {
                        return new GnomeXMLDOMElement(child);
                }
                else
                {
                        return new GnomeXMLDOMNode(child);
                }
        }
        else
        {
                return 0;
        }
}

#endif // LOG4CXX_HAVE_LIBXML2
