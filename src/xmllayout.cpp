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

#include <log4cxx/xml/xmllayout.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/transform.h>
#include <log4cxx/helpers/iso8601dateformat.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/transcoder.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;
using namespace log4cxx::spi::location;
using namespace log4cxx::xml;

IMPLEMENT_LOG4CXX_OBJECT(XMLLayout)

XMLLayout::XMLLayout()
: locationInfo(false)
{
}

void XMLLayout::setOption(const LogString& option,
        const LogString& value)
{
        if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("LOCATIONINFO"), LOG4CXX_STR("locationinfo")))
        {
                setLocationInfo(OptionConverter::toBoolean(value, false));
        }
}

void XMLLayout::format(LogString& output,
     const spi::LoggingEventPtr& event,
     Pool& p) const
{
        output.append(LOG4CXX_STR("<log4j:event logger=\""));
        output.append(event->getLoggerName());
        output.append(LOG4CXX_STR("\" timestamp=\""));
        output.append(StringHelper::toString(event->getTimeStamp()/1000, p));
        output.append(LOG4CXX_STR("\" level=\""));
        output.append(event->getLevel()->toString());
        output.append(LOG4CXX_STR("\" thread=\""));
        output.append(StringHelper::toString(event->getThreadId(), p));
        output.append(LOG4CXX_STR("\">\n"));

        output.append(LOG4CXX_STR("<log4j:message><![CDATA["));
        // Append the rendered message. Also make sure to escape any
        // existing CDATA sections.
        Transform::appendEscapingCDATA(output, event->getRenderedMessage());
        output.append(LOG4CXX_STR("]]></log4j:message>\n"));

        const LogString& ndc = event->getNDC();
        if(!ndc.empty())
        {
                output.append(LOG4CXX_STR("<log4j:NDC><![CDATA["));
                output.append(ndc);
                output.append(LOG4CXX_STR("]]></log4j:NDC>\n"));
        }

        //
        //  TODO: looks pretty inefficient if empty
        //
        std::set<LogString> mdcKeySet = event->getMDCKeySet();

        if(!mdcKeySet.empty()) {
                /**
                * Normally a sort isn't required, but for Test Case purposes
                * we need to guarantee a particular order.
                *
                * Besides which, from a human readable point of view, the sorting
                * of the keys is kinda nice..
                */

                output.append(LOG4CXX_STR("<log4j:MDC>\n"));
                for (std::set<LogString>::iterator i = mdcKeySet.begin();
                        i != mdcKeySet.end(); i++)
                {
                        LogString propName = *i;
                        LogString propValue = event->getMDC(propName);
                        output.append(LOG4CXX_STR("    <log4j:data name=\""));
                        output.append(propName);
                        output.append(LOG4CXX_STR("\" value=\""));
                        output.append(propValue);
                        output.append(LOG4CXX_STR("\"/>\n"));
                }
                output.append(LOG4CXX_STR("</log4j:MDC>\n"));
    }

        if(locationInfo)
        {
                output.append(LOG4CXX_STR("<log4j:locationInfo class=\""));
                const LocationInfo& locInfo = event->getLocationInformation();
                LOG4CXX_DECODE_CHAR(className, locInfo.getClassName());
                output.append(className);
                output.append(LOG4CXX_STR("\" method=\""));
                LOG4CXX_DECODE_CHAR(method, locInfo.getMethodName());
                output.append(method);
                output.append(LOG4CXX_STR("\" file=\""));
                LOG4CXX_DECODE_CHAR(fileName, locInfo.getFileName());
                output.append(fileName);
                output.append(LOG4CXX_STR("\" line=\""));
                output.append(StringHelper::toString(locInfo.getLineNumber(), p));
                output.append(LOG4CXX_STR("\"/>\n"));
        }

    std::set<LogString> propertySet = event->getPropertyKeySet();

    if (!propertySet.empty())
        {
                output.append(LOG4CXX_STR("<log4j:properties>\n"));
                for (std::set<LogString>::iterator i = propertySet.begin();
                        i != propertySet.end(); i++)
                {
                        LogString propName = *i;
                        output .append(LOG4CXX_STR("<log4j:data name=\""));
                        output.append(propName);
                        LogString propValue = event->getProperty(propName);
                        output.append(LOG4CXX_STR("\" value=\""));
                        output.append(propValue);
                        output.append(LOG4CXX_STR("\"/>\n"));
                }
                output.append(LOG4CXX_STR("</log4j:properties>\n"));
    }

        output.append(LOG4CXX_STR("</log4j:event>\n"));
}

