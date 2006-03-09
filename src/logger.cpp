/*
 * Copyright 2003-2006 The Apache Software Foundation.
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

#include <log4cxx/logger.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/spi/loggerfactory.h>
#include <log4cxx/appender.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/synchronized.h>
#include <log4cxx/helpers/transcoder.h>
#include <stdarg.h>
#include <log4cxx/helpers/appenderattachableimpl.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/aprinitializer.h>
#include <log4cxx/private/log4cxx_private.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(Logger)

Logger::Logger(const LogString& name)
: name(name), level(), parent(), resourceBundle(),
repository(0), aai(), additive(true),  mutex()
{
}

Logger::~Logger()
{
}




void Logger::addAppender(const AppenderPtr& newAppender)
{
        synchronized sync(mutex);

        if (aai == 0)
        {
                  aai = new AppenderAttachableImpl();
        }
        aai->addAppender(newAppender);
		if (repository != 0) {
           repository->fireAddAppenderEvent(this, newAppender);
		}
}


void Logger::callAppenders(const spi::LoggingEventPtr& event, Pool& p)
{
        int writes = 0;

        for(LoggerPtr logger = this; logger != 0; logger = logger->parent)
        {
                // Protected against simultaneous call to addAppender, removeAppender,...
                synchronized sync(logger->mutex);

                if (logger->aai != 0)
                {
                        writes += logger->aai->appendLoopOnAppenders(event, p);
                }

                if(!logger->additive)
                {
                        break;
                }
        }

        if(writes == 0 && repository != 0)
        {
                repository->emitNoAppenderWarning(this);
        }
}

void Logger::closeNestedAppenders()
{
    AppenderList appenders = getAllAppenders();
    for(AppenderList::iterator it=appenders.begin(); it!=appenders.end(); ++it)
    {
       (*it)->close();
    }
}


void Logger::forcedLog(const LevelPtr& level, const std::string& message,
        const LocationInfo& location)
{
        Pool p;
        LOG4CXX_DECODE_CHAR(msg, message);
        LoggingEventPtr event(new LoggingEvent(this, level, msg, location));
        callAppenders(event, p);
}

#if LOG4CXX_HAS_WCHAR_T
void Logger::forcedLog(const LevelPtr& level, const std::wstring& message,
        const LocationInfo& location)
{
        Pool p;
        LOG4CXX_DECODE_WCHAR(msg, message);
        LoggingEventPtr event(new LoggingEvent(this, level, msg, location));
        callAppenders(event, p);
}
#endif

void Logger::forcedLog(const LevelPtr& level, const std::string& message)
{
        Pool p;
        LOG4CXX_DECODE_CHAR(msg, message);
        LoggingEventPtr event(new LoggingEvent(this, level, msg,
              LocationInfo::getLocationUnavailable()));
        callAppenders(event, p);
}

#if LOG4CXX_HAS_WCHAR_T
void Logger::forcedLog(const LevelPtr& level, const std::wstring& message)
{
        Pool p;
        LOG4CXX_DECODE_WCHAR(msg, message);
        LoggingEventPtr event(new LoggingEvent(this, level, msg,
           LocationInfo::getLocationUnavailable()));
        callAppenders(event, p);
}
#endif


bool Logger::getAdditivity() const
{
        return additive;
}

AppenderList Logger::getAllAppenders() const
{
        synchronized sync(mutex);

        if (aai == 0)
        {
                return AppenderList();
        }
        else
        {
                return aai->getAllAppenders();
        }
}

AppenderPtr Logger::getAppender(const LogString& name) const
{
        synchronized sync(mutex);

        if (aai == 0 || name.empty())
        {
                return 0;
        }

        return aai->getAppender(name);
}

const LevelPtr& Logger::getEffectiveLevel() const
{
        for(const Logger * l = this; l != 0; l=l->parent)
        {
                if(l->level != 0)
                {
                        return l->level;
                }
        }

        throw NullPointerException("No level specified for logger or ancestors.");
#if LOG4CXX_RETURN_AFTER_THROW
        return this->level;
#endif
}

LoggerRepositoryPtr Logger::getLoggerRepository() const
{
        return repository;
}

ResourceBundlePtr Logger::getResourceBundle() const
{
        for (LoggerPtr l = this; l != 0; l = l->parent)
        {
                if (l->resourceBundle != 0)
                {
                        return l->resourceBundle;
                }
        }

        // It might be the case that there is no resource bundle
        return 0;
}

#if 0
String Logger::getResourceBundleString(const String& key) const
{
        ResourceBundlePtr rb = getResourceBundle();

        // This is one of the rare cases where we can use logging in order
        // to report errors from within log4j.
        if (rb == 0)
        {
                return String();
        }
        else
        {
                try
                {
                        return rb->getString(key);
                }
                catch (MissingResourceException&)
                {
                        ((Logger *)this)->error(LOG4CXX_WSTR("No resource is associated with key \"") +
                                key + LOG4CXX_WSTR("\"."));

                        return String();
                }
        }
}
#endif

const LoggerPtr& Logger::getParent() const
{
        return parent;
}

const LevelPtr& Logger::getLevel() const
{
        return level;
}


bool Logger::isAttached(const AppenderPtr& appender) const
{
        synchronized sync(mutex);

        if (appender == 0 || aai == 0)
        {
                return false;
        }
        else
        {
                return aai->isAttached(appender);
        }
}

bool Logger::isDebugEnabled() const
{
        if(repository == 0 || repository->isDisabled(Level::DEBUG_INT))
        {
                return false;
        }

        return Level::getDebug()->isGreaterOrEqual(getEffectiveLevel());
}

bool Logger::isEnabledFor(const LevelPtr& level) const
{
        if(repository == 0 || repository->isDisabled(level->toInt()))
        {
                return false;
        }

        return level->isGreaterOrEqual(getEffectiveLevel());
}


bool Logger::isInfoEnabled() const
{
        if(repository == 0 || repository->isDisabled(Level::INFO_INT))
        {
                return false;
        }

        return Level::getInfo()->isGreaterOrEqual(getEffectiveLevel());
}

bool Logger::isErrorEnabled() const
{
        if(repository == 0 || repository->isDisabled(Level::ERROR_INT))
        {
                return false;
        }

        return Level::getError()->isGreaterOrEqual(getEffectiveLevel());
}

bool Logger::isWarnEnabled() const
{
        if(repository == 0 || repository->isDisabled(Level::WARN_INT))
        {
                return false;
        }

        return Level::getWarn()->isGreaterOrEqual(getEffectiveLevel());
}

bool Logger::isFatalEnabled() const
{
        if(repository == 0 || repository->isDisabled(Level::FATAL_INT))
        {
                return false;
        }

        return Level::getFatal()->isGreaterOrEqual(getEffectiveLevel());
}

/*void Logger::l7dlog(const LevelPtr& level, const String& key,
                        const char* file, int line)
{
        if (repository == 0 || repository->isDisabled(level->level))
        {
                return;
        }

        if (level->isGreaterOrEqual(getEffectiveLevel()))
        {
                String msg = getResourceBundleString(key);

                // if message corresponding to 'key' could not be found in the
                // resource bundle, then default to 'key'.
                if (msg.empty())
                {
                        msg = key;
                }

                forcedLog(FQCN, level, msg, file, line);
        }
}*/

void Logger::l7dlog(const LevelPtr& level, const std::string& key,
                        const LocationInfo& location, ...)
{
        if (repository == 0 || repository->isDisabled(level->toInt()))
        {
                return;
        }

        if (level->isGreaterOrEqual(getEffectiveLevel()))
        {
#if 0
//    TODO
                String pattern = getResourceBundleString(key);
                String msg;

                if (pattern.empty())
                {
                        msg = key;
                }
                else
                {
                        va_list params;
                        va_start (params, line);
                        msg = StringHelper::format(pattern, params);
                        va_end (params);
                }
#endif
                forcedLog(level, key, location);
        }
}

#if LOG4CXX_HAS_WCHAR_T
void Logger::l7dlog(const LevelPtr& level, const std::wstring& key,
                        const LocationInfo& location, ...)
{
        if (repository == 0 || repository->isDisabled(level->toInt()))
        {
                return;
        }

        if (level->isGreaterOrEqual(getEffectiveLevel()))
        {
#if 0
//    TODO
                String pattern = getResourceBundleString(key);
                String msg;

                if (pattern.empty())
                {
                        msg = key;
                }
                else
                {
                        va_list params;
                        va_start (params, line);
                        msg = StringHelper::format(pattern, params);
                        va_end (params);
                }
#endif
                forcedLog(level, key, location);
        }
}
#endif

void Logger::removeAllAppenders()
{
        synchronized sync(mutex);

        if(aai != 0)
        {
                aai->removeAllAppenders();
                aai = 0;
        }
}

void Logger::removeAppender(const AppenderPtr& appender)
{
        synchronized sync(mutex);

        if(appender == 0 || aai == 0)
        {
                return;
        }

        aai->removeAppender(appender);
}

void Logger::removeAppender(const LogString& name)
{
        synchronized sync(mutex);

        if(name.empty() || aai == 0)
        {
                return;
        }

        aai->removeAppender(name);
}

void Logger::setAdditivity(bool additive)
{
        this->additive = additive;
}

void Logger::setHierarchy(spi::LoggerRepository * repository)
{
        this->repository = repository;
}

void Logger::setLevel(const LevelPtr& level)
{
        this->level = level;
}



LoggerPtr Logger::getLogger(const std::string& name)
{
        LOG4CXX_DECODE_CHAR(lname, name);
        return LogManager::getLogger(lname);
}

#if LOG4CXX_HAS_WCHAR_T
LoggerPtr Logger::getLogger(const std::wstring& name)
{
        LOG4CXX_DECODE_WCHAR(lname, name);
        return LogManager::getLogger(lname);
}
#endif

LoggerPtr Logger::getLogger(const char* const name)
{
        LogString lname;
        Transcoder::decode(name, strlen(name), lname);
        return LogManager::getLogger(lname);
}

#if LOG4CXX_HAS_WCHAR_T
LoggerPtr Logger::getLogger(const wchar_t* const name)
{
        LogString lname;
        Transcoder::decode(name, wcslen(name), lname);
        return LogManager::getLogger(lname);
}
#endif


LoggerPtr Logger::getRootLogger() {
        return LogManager::getRootLogger();
}

LoggerPtr Logger::getLogger(const LogString& name,
        const spi::LoggerFactoryPtr& factory)
{
        return LogManager::getLogger(name, factory);
}

void Logger::getName(std::string& rv) const {
    Transcoder::encode(name, rv);
}

#if LOG4CXX_HAS_WCHAR_T
void Logger::getName(std::wstring& rv) const {
    Transcoder::encode(name, rv);
}
#endif

void Logger::debug(const std::string& msg, const log4cxx::spi::LocationInfo& location) {
  if (isEnabledFor(log4cxx::Level::getDebug())) {
    forcedLog(log4cxx::Level::getDebug(), msg, location);
  }
}

#if LOG4CXX_HAS_WCHAR_T
void Logger::debug(const std::wstring& msg, const log4cxx::spi::LocationInfo& location) {
  if (isEnabledFor(log4cxx::Level::getDebug())) {
    forcedLog(log4cxx::Level::getDebug(), msg, location);
  }
}
#endif

void Logger::debug(const std::string& msg) {
  if (isEnabledFor(log4cxx::Level::getDebug())) {
    forcedLog(log4cxx::Level::getDebug(), msg);
  }
}

#if LOG4CXX_HAS_WCHAR_T
void Logger::debug(const std::wstring& msg) {
  if (isEnabledFor(log4cxx::Level::getDebug())) {
    forcedLog(log4cxx::Level::getDebug(), msg);
  }
}
#endif

#if LOG4CXX_HAS_WCHAR_T
void Logger::error(const std::wstring& msg, const log4cxx::spi::LocationInfo& location) {
  if (isEnabledFor(log4cxx::Level::getError())) {
     forcedLog(log4cxx::Level::getError(), msg, location);
  }
}
#endif

void Logger::error(const std::string& msg, const log4cxx::spi::LocationInfo& location) {
  if (isEnabledFor(log4cxx::Level::getError())) {
     forcedLog(log4cxx::Level::getError(), msg, location);
  }
}

#if LOG4CXX_HAS_WCHAR_T
void Logger::error(const std::wstring& msg) {
  if (isEnabledFor(log4cxx::Level::getError())) {
     forcedLog(log4cxx::Level::getError(), msg);
  }
}
#endif

void Logger::error(const std::string& msg) {
  if (isEnabledFor(log4cxx::Level::getError())) {
     forcedLog(log4cxx::Level::getError(), msg);
  }
}

#if LOG4CXX_HAS_WCHAR_T
void Logger::fatal(const std::wstring& msg, const log4cxx::spi::LocationInfo& location) {
  if (isEnabledFor(log4cxx::Level::getFatal())) {
    forcedLog(log4cxx::Level::getFatal(), msg, location);
  }
}
#endif

void Logger::fatal(const std::string& msg, const log4cxx::spi::LocationInfo& location) {
  if (isEnabledFor(log4cxx::Level::getFatal())) {
    forcedLog(log4cxx::Level::getFatal(), msg, location);
  }
}

#if LOG4CXX_HAS_WCHAR_T
void Logger::fatal(const std::wstring& msg) {
  if (isEnabledFor(log4cxx::Level::getFatal())) {
    forcedLog(log4cxx::Level::getFatal(), msg);
  }
}
#endif

void Logger::fatal(const std::string& msg) {
  if (isEnabledFor(log4cxx::Level::getFatal())) {
    forcedLog(log4cxx::Level::getFatal(), msg);
  }
}

#if LOG4CXX_HAS_WCHAR_T
void Logger::info(const std::wstring& msg, const log4cxx::spi::LocationInfo& location) {
  if (isEnabledFor(log4cxx::Level::getInfo())) {
    forcedLog(log4cxx::Level::getInfo(), msg, location);
  }
}
#endif

void Logger::info(const std::string& msg, const log4cxx::spi::LocationInfo& location) {
  if (isEnabledFor(log4cxx::Level::getInfo())) {
    forcedLog(log4cxx::Level::getInfo(), msg, location);
  }
}

#if LOG4CXX_HAS_WCHAR_T
void Logger::info(const std::wstring& msg) {
  if (isEnabledFor(log4cxx::Level::getInfo())) {
    forcedLog(log4cxx::Level::getInfo(), msg);
  }
}
#endif

void Logger::info(const std::string& msg) {
  if (isEnabledFor(log4cxx::Level::getInfo())) {
    forcedLog(log4cxx::Level::getInfo(), msg);
  }
}

#if LOG4CXX_HAS_WCHAR_T
void Logger::log(const LevelPtr& level, const std::wstring& message,
    const log4cxx::spi::LocationInfo& location) {
    if (isEnabledFor(level)) {
      forcedLog(level, message, location);
    }
}
#endif

void Logger::log(const LevelPtr& level, const std::string& message,
    const log4cxx::spi::LocationInfo& location) {
    if (isEnabledFor(level)) {
      forcedLog(level, message, location);
    }
}

#if LOG4CXX_HAS_WCHAR_T
void Logger::log(const LevelPtr& level, const std::wstring& message) {
    if (isEnabledFor(level)) {
      forcedLog(level, message);
    }
}
#endif

void Logger::log(const LevelPtr& level, const std::string& message) {
    if (isEnabledFor(level)) {
      forcedLog(level, message);
    }
}

#if LOG4CXX_HAS_WCHAR_T
void Logger::warn(const std::wstring& msg, const log4cxx::spi::LocationInfo& location) {
  if (isEnabledFor(log4cxx::Level::getWarn())) {
    forcedLog(log4cxx::Level::getWarn(), msg, location);
  }
}
#endif

void Logger::warn(const std::string& msg, const log4cxx::spi::LocationInfo& location) {
  if (isEnabledFor(log4cxx::Level::getWarn())) {
    forcedLog(log4cxx::Level::getWarn(), msg, location);
  }
}

#if LOG4CXX_HAS_WCHAR_T
void Logger::warn(const std::wstring& msg) {
  if (isEnabledFor(log4cxx::Level::getWarn())) {
    forcedLog(log4cxx::Level::getWarn(), msg);
  }
}
#endif

void Logger::warn(const std::string& msg) {
  if (isEnabledFor(log4cxx::Level::getWarn())) {
    forcedLog(log4cxx::Level::getWarn(), msg);
  }
}
