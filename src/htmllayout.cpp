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

#include <log4cxx/htmllayout.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/transform.h>
#include <log4cxx/helpers/iso8601dateformat.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/transcoder.h>

#include <apr_pools.h>
#include <apr_time.h>
#include <apr_strings.h>
#include <string.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(HTMLLayout)


HTMLLayout::HTMLLayout()
: locationInfo(false), title(LOG4CXX_STR("Log4cxx Log Messages")),
dateFormat()
{
   dateFormat.setTimeZone(TimeZone::getGMT());
}


void HTMLLayout::setOption(const LogString& option,
        const LogString& value)
{

        if (StringHelper::equalsIgnoreCase(option,
               LOG4CXX_STR("TITLE"), LOG4CXX_STR("title")))
        {
                setTitle(value);
        }
        else if (StringHelper::equalsIgnoreCase(option,
               LOG4CXX_STR("LOCATIONINFO"), LOG4CXX_STR("locationinfo")))
        {
                setLocationInfo(OptionConverter::toBoolean(value, false));
        }
}

void HTMLLayout::format(LogString& output,
     const spi::LoggingEventPtr& event,
     Pool& pool) const
{
        output.append(LOG4CXX_EOL LOG4CXX_STR("<tr>") LOG4CXX_EOL LOG4CXX_STR("<td>"));

        dateFormat.format(output, event->getTimeStamp(), pool);


        output.append(LOG4CXX_STR("</td>") LOG4CXX_EOL);

        output.append(LOG4CXX_STR("<td title=\""));
        LogString threadName(event->getThreadName());
        output.append(threadName);
        output.append(LOG4CXX_STR(" thread\">"));
        output.append(threadName);
        output.append(LOG4CXX_STR("</td>") LOG4CXX_EOL);

        output.append(LOG4CXX_STR("<td title=\"Level\">"));
        if (event->getLevel()->equals(Level::getDebug()))
        {
                output.append(LOG4CXX_STR("<font color=\"#339933\">"));
                output.append(event->getLevel()->toString());
                output.append(LOG4CXX_STR("</font>"));
        }
        else if(event->getLevel()->isGreaterOrEqual(Level::getWarn()))
        {
                output.append(LOG4CXX_STR("<font color=\"#993300\"><strong>"));
                output.append(event->getLevel()->toString());
                output.append(LOG4CXX_STR("</strong></font>"));
        }
        else
        {
                output.append(event->getLevel()->toString());
        }

        output.append(LOG4CXX_STR("</td>") LOG4CXX_EOL);

        output.append(LOG4CXX_STR("<td title=\""));
        output.append(event->getLoggerName());
        output.append(LOG4CXX_STR(" category\">"));
        Transform::appendEscapingTags(output, event->getLoggerName());
        output.append(LOG4CXX_STR("</td>") LOG4CXX_EOL);

        if(locationInfo)
        {
                output.append(LOG4CXX_STR("<td>"));
                const LocationInfo& locInfo = event->getLocationInformation();
                LOG4CXX_DECODE_CHAR(fileName, locInfo.getFileName());
                Transform::appendEscapingTags(output, fileName);
                output.append(1, LOG4CXX_STR(':'));
                int line = event->getLocationInformation().getLineNumber();
                if (line != 0)
                {
                        output.append(StringHelper::toString(line, pool));
                }
                output.append(LOG4CXX_STR("</td>") LOG4CXX_EOL);
        }

        output.append(LOG4CXX_STR("<td title=\"Message\">"));
        Transform::appendEscapingTags(output, event->getRenderedMessage());
        output.append(LOG4CXX_STR("</td>") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("</tr>") LOG4CXX_EOL);

        if (event->getNDC().length() != 0)
        {
                output.append(LOG4CXX_STR("<tr><td bgcolor=\"#EEEEEE\" "));
                output.append(LOG4CXX_STR("style=\"font-size : xx-small;\" colspan=\"6\" "));
                output.append(LOG4CXX_STR("title=\"Nested Diagnostic Context\">"));
                output.append(LOG4CXX_STR("NDC: "));
                Transform::appendEscapingTags(output, event->getNDC());
                output.append(LOG4CXX_STR("</td></tr>") LOG4CXX_EOL);
        }
}

void HTMLLayout::appendHeader(LogString& output, Pool& pool)
{
        output.append(LOG4CXX_STR("<!DOCTYPE HTML PUBLIC "));
        output.append(LOG4CXX_STR("\"-//W3C//DTD HTML 4.01 Transitional//EN\" "));
        output.append(LOG4CXX_STR("\"http://www.w3.org/TR/html4/loose.dtd\">") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("<html>") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("<head>") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("<title>"));
        output.append(title);
        output.append(LOG4CXX_STR("</title>") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("<style type=\"text/css\">") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("<!--") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("body, table {font-family: arial,sans-serif; font-size: x-small;}") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("th {background: #336699; color: #FFFFFF; text-align: left;}") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("-->") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("</style>") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("</head>") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("<body bgcolor=\"#FFFFFF\" topmargin=\"6\" leftmargin=\"6\">") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("<hr size=\"1\" noshade>") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("Log session start time "));

        dateFormat.format(output, apr_time_now(), pool);

        output.append(LOG4CXX_STR("<br>") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("<br>") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("<table cellspacing=\"0\" cellpadding=\"4\" border=\"1\" bordercolor=\"#224466\" width=\"100%\">") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("<tr>") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("<th>Time</th>") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("<th>Thread</th>") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("<th>Level</th>") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("<th>Category</th>") LOG4CXX_EOL);
        if(locationInfo)
        {
                output.append(LOG4CXX_STR("<th>File:Line</th>") LOG4CXX_EOL);
        }
        output.append(LOG4CXX_STR("<th>Message</th>") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("</tr>") LOG4CXX_EOL);
}

void HTMLLayout::appendFooter(LogString& output, Pool& pool)
{
        output.append(LOG4CXX_STR("</table>") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("<br>") LOG4CXX_EOL);
        output.append(LOG4CXX_STR("</body></html>"));
}
