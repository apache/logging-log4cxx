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

#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/ndc.h>

#include <log4cxx/level.h>
#include <log4cxx/helpers/socketoutputstream.h>
#include <log4cxx/helpers/socketinputstream.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/system.h>
#include <log4cxx/helpers/loader.h>
#include <log4cxx/helpers/socket.h>
#include <log4cxx/helpers/aprinitializer.h>
#include <log4cxx/helpers/threadspecificdata.h>
#include <log4cxx/helpers/transcoder.h>

#include <apr_time.h>
#include <apr_portable.h>
#include <apr_strings.h>
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(LoggingEvent)


//
//   Accessor for start time.
//
log4cxx_time_t LoggingEvent::getStartTime() {
  return log4cxx::helpers::APRInitializer::initialize();
}

LoggingEvent::LoggingEvent() :
   ndc(LOG4CXX_STR("null")),
   properties(0),
   ndcLookupRequired(true),
   mdcCopyLookupRequired(true),
   timeStamp(0),
   locationInfo() {
}

LoggingEvent::LoggingEvent(
        const LoggerPtr& logger1, const LevelPtr& level1,
        const LogString& message1, const LocationInfo& locationInfo1) :
   logger(logger1),
   level(level1),
   ndc(LOG4CXX_STR("null")),
   properties(0),
   ndcLookupRequired(true),
   mdcCopyLookupRequired(true),
   message(message1),
   timeStamp(apr_time_now()),
   locationInfo(locationInfo1),
   threadName(getCurrentThreadName()) {
}

LoggingEvent::~LoggingEvent()
{
        if (properties != 0)
        {
                delete properties;
        }
}

const LogString LoggingEvent::getLoggerName() const
{
        return logger->getName();
}

const LogString& LoggingEvent::getNDC() const
{
        if(ndcLookupRequired)
        {
                ((LoggingEvent *)this)->ndcLookupRequired = false;
                ((LoggingEvent *)this)->ndc = NDC::get();
        }

        return ndc;
}

LogString LoggingEvent::getMDC(const LogString& key) const
{
   // Note the mdcCopy is used if it exists. Otherwise we use the MDC
    // that is associated with the thread.
    if (!mdcCopy.empty())
        {
                MDC::Map::const_iterator it = mdcCopy.find(key);

                if (it != mdcCopy.end())
                {
                        if (!it->second.empty())
                        {
                                return it->second;
                        }
                }
    }

    return MDC::get(key);

}

std::set<LogString> LoggingEvent::getMDCKeySet() const
{
        std::set<LogString> set;

        if (!mdcCopy.empty())
        {
                MDC::Map::const_iterator it;
                for (it = mdcCopy.begin(); it != mdcCopy.end(); it++)
                {
                        set.insert(it->first);

                }
        }
        else
        {
                MDC::Map& m = ThreadSpecificData::getCurrentThreadMap();

                MDC::Map::const_iterator it;
                for (it = m.begin(); it != m.end(); it++)
                {
                        set.insert(it->first);
                }
        }

        return set;
}

void LoggingEvent::getMDCCopy() const
{
        if(mdcCopyLookupRequired)
        {
                ((LoggingEvent *)this)->mdcCopyLookupRequired = false;
                // the clone call is required for asynchronous logging.
                ((LoggingEvent *)this)->mdcCopy = ThreadSpecificData::getCurrentThreadMap();
        }
}

LogString LoggingEvent::getProperty(const LogString& key) const
{
        if (properties == 0)
        {
                return LogString();
        }

        std::map<LogString, LogString>::const_iterator  it = properties->find(key);

        if (it != properties->end())
        {
                const LogString& p = it->second;

                if (!p.empty())
                {
                        return p;
                }
        }

        return LogString();
}

std::set<LogString> LoggingEvent::getPropertyKeySet() const
{
        std::set<LogString> set;

        if (properties != 0)
        {
                std::map<LogString, LogString>::const_iterator it;
                for (it = properties->begin(); it != properties->end(); it++)
                {
                        set.insert(it->first);
                }
        }

        return set;
}


const LogString LoggingEvent::getCurrentThreadName() {
#if APR_HAS_THREADS
#if defined(_WIN32)
   char result[20];
   DWORD threadId = GetCurrentThreadId();
   apr_snprintf(result, sizeof(result), "0x%.8x", threadId);
#else
   // apr_os_thread_t encoded in HEX takes needs as many characters
   // as two times the size of the type, plus an additional null byte
   char result[sizeof(apr_os_thread_t) * 2 + 10];
   result[0] = '0';
   result[1] = 'x';   apr_os_thread_t threadId = apr_os_thread_current();
   apr_snprintf(result+2, (sizeof result) - 2, "%pt", &threadId);
#endif
   LOG4CXX_DECODE_CHAR(str, (const char*) result);
   return str;
#else
   return LOG4CXX_STR("0x00000000");
#endif
}

void LoggingEvent::read(const helpers::SocketInputStreamPtr& /* is */)
{
#if 0
        // fqnOfCategoryClass
        is->read(fqnOfCategoryClass);

        // name
        LogString name;
        is->read(name);
        logger = Logger::getLogger(name);

        // level
        readLevel(is);

        // message
        is->read(message);

        // timeStamp
        is->read(&timeStamp, sizeof(timeStamp));

        // file
        String buffer;
        is->read(buffer);

        if (!buffer.empty())
        {
                USES_CONVERSION;
                fileFromStream = T2A(buffer.c_str());
                file = (char *)fileFromStream.c_str();
        }

        // line
        is->read(line);

        // ndc
        is->read(ndc);
        ndcLookupRequired = false;

        // mdc
        String key, value;
        int n, size;
        is->read(size);
        for (n = 0; n < size; n++)
        {
                is->read(key);
                is->read(value);
                mdcCopy[key] = value;
        }
        mdcCopyLookupRequired = false;

        // properties
        is->read(size);
        for (n = 0; n < size; n++)
        {
                is->read(key);
                is->read(value);
                setProperty(key, value);
        }

        // threadId
        is->read(threadId);
#endif
}

void LoggingEvent::readLevel(const helpers::SocketInputStreamPtr& /* is */)
{
  #if 0
        int levelInt;
        is->read(levelInt);

    String className;
        is->read(className);

        if (className.empty())
        {
                level = Level::toLevel(levelInt);
        }
        else try
        {
                Level::LevelClass& levelClass =
                        (Level::LevelClass&)Loader::loadClass(className);
                level = levelClass.toLevel(levelInt);
        }
        catch (Exception& oops)
        {
                LogLog::warn(
                        _T("Level deserialization failed, reverting to default."), oops);
                level = Level::toLevel(levelInt);
        }
        catch (...)
        {
                LogLog::warn(
                        _T("Level deserialization failed, reverting to default."));
                level = Level::toLevel(levelInt);
        }
#endif
}

void LoggingEvent::setProperty(const LogString& key, const LogString& value)
{
        if (properties == 0)
        {
                properties = new std::map<LogString, LogString>;
        }

        (*properties)[key] = value;
}

void LoggingEvent::write(helpers::SocketOutputStreamPtr& /* os */) const
{
  #if 0
        // fqnOfCategoryClass
        os->write(fqnOfCategoryClass);

        // name
        os->write(logger->getName());

        // level
        writeLevel(os);

        // message
        os->write(message);

        // timeStamp
        os->write(&timeStamp, sizeof(timeStamp));

        // file
        String buffer;
        if (file != 0)
        {
                USES_CONVERSION;
                buffer = A2T(file);
        }
        os->write(buffer);

        // line
        os->write(line);

        // ndc
        os->write(getNDC());

        // mdc
        getMDCCopy();
        os->write((int)mdcCopy.size());
        MDC::Map::const_iterator it;
        for (it = mdcCopy.begin(); it != mdcCopy.end(); it++)
        {
                os->write(it->first);
                os->write(it->second);
        }

        // properties
        int size = (properties != 0) ? (int)properties->size() : 0;
        os->write(size);

        if (size > 0)
        {
                std::map<String, String>::const_iterator it;
                for (it = properties->begin(); it != properties->end(); it++)
                {
                        os->write(it->first);
                        os->write(it->second);
                }
        }

        // threadId
        os->write(threadId);
#endif
}

void LoggingEvent::writeLevel(helpers::SocketOutputStreamPtr& /* os */) const
{
#if 0
        os->write(level->toInt());

        const Class& clazz = level->getClass();

        if (&clazz == &Level::getStaticClass())
        {
                os->write(String());
        }
        else
        {
                os->write(clazz.getName());
        }
#endif
}

