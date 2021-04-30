/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <log4cxx/logstring.h>
#include <log4cxx/logger.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/spi/loggerfactory.h>
#include <log4cxx/appender.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/appenderattachableimpl.h>
#include <log4cxx/helpers/exception.h>
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/private/log4cxx_private.h>
#include <log4cxx/helpers/aprinitializer.h>
#include <mutex>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(Logger)

Logger::Logger(Pool& p, const LogString& name1)
	: pool(&p), name(), level(), parent(), resourceBundle(),
	  repository(), aai(new AppenderAttachableImpl(*pool))
{
	name = name1;
	additive = true;
}

Logger::~Logger()
{
}

void Logger::addAppender(const AppenderPtr newAppender)
{
	log4cxx::spi::LoggerRepositoryPtr rep;

	aai->addAppender(newAppender);
	rep = repository.lock();

	if (rep)
	{
		rep->fireAddAppenderEvent(this, newAppender.get());
	}
}

void Logger::reconfigure( const std::vector<AppenderPtr>& appenders, bool additive1 )
{
	std::unique_lock<log4cxx::shared_mutex> lock(mutex);

	additive = additive1;

	aai->removeAllAppenders();

	for ( std::vector<AppenderPtr>::const_iterator it = appenders.cbegin();
		it != appenders.cend();
		it++ )
	{
		aai->addAppender( *it );

		if (log4cxx::spi::LoggerRepositoryPtr rep = repository.lock())
		{
			rep->fireAddAppenderEvent(this, it->get());
		}
	}
}

void Logger::callAppenders(const spi::LoggingEventPtr& event, Pool& p) const
{
	int writes = 0;

	for (const Logger* logger = this;
		logger != 0;
		logger = logger->parent.get())
	{
		writes += logger->aai->appendLoopOnAppenders(event, p);

		if (!logger->additive)
		{
			break;
		}
	}

	log4cxx::spi::LoggerRepositoryPtr rep = repository.lock();
	if (writes == 0 && rep)
	{
		rep->emitNoAppenderWarning(const_cast<Logger*>(this));
	}
}

void Logger::closeNestedAppenders()
{
	AppenderList appenders = getAllAppenders();

	for (AppenderList::iterator it = appenders.begin(); it != appenders.end(); ++it)
	{
		(*it)->close();
	}
}


void Logger::forcedLog(const LevelPtr& level1, const std::string& message,
	const LocationInfo& location) const
{
	Pool p;
	LOG4CXX_DECODE_CHAR(msg, message);
	LoggingEventPtr event(new LoggingEvent(name, level1, msg, location));
	callAppenders(event, p);
}


void Logger::forcedLog(const LevelPtr& level1, const std::string& message) const
{
	Pool p;
	LOG4CXX_DECODE_CHAR(msg, message);
	LoggingEventPtr event(new LoggingEvent(name, level1, msg,
			LocationInfo::getLocationUnavailable()));
	callAppenders(event, p);
}

void Logger::forcedLogLS(const LevelPtr& level1, const LogString& message,
	const LocationInfo& location) const
{
	Pool p;
	LoggingEventPtr event(new LoggingEvent(name, level1, message, location));
	callAppenders(event, p);
}


bool Logger::getAdditivity() const
{
	return additive;
}

AppenderList Logger::getAllAppenders() const
{
	return aai->getAllAppenders();
}

AppenderPtr Logger::getAppender(const LogString& name1) const
{
	return aai->getAppender(name1);
}

const LevelPtr Logger::getEffectiveLevel() const
{
	for (const Logger* l = this; l != 0; l = l->parent.get())
	{
		if (l->level != 0)
		{
			return l->level;
		}
	}

	throw NullPointerException(LOG4CXX_STR("No level specified for logger or ancestors."));
#if LOG4CXX_RETURN_AFTER_THROW
	return this->level;
#endif
}

LoggerRepositoryWeakPtr Logger::getLoggerRepository() const
{
	return repository;
}

ResourceBundlePtr Logger::getResourceBundle() const
{
	for (const Logger* l = this; l != 0; l = l->parent.get())
	{
		if (l->resourceBundle != 0)
		{
			return l->resourceBundle;
		}
	}

	// It might be the case that there is no resource bundle
	return 0;
}


LogString Logger::getResourceBundleString(const LogString& key) const
{
	ResourceBundlePtr rb = getResourceBundle();

	// This is one of the rare cases where we can use logging in order
	// to report errors from within log4j.
	if (rb == 0)
	{
		return LogString();
	}
	else
	{
		try
		{
			return rb->getString(key);
		}
		catch (MissingResourceException&)
		{
			logLS(Level::getError(), LOG4CXX_STR("No resource is associated with key \"") +
				key + LOG4CXX_STR("\"."), LocationInfo::getLocationUnavailable());

			return LogString();
		}
	}
}


LoggerPtr Logger::getParent() const
{
	return parent;
}

LevelPtr Logger::getLevel() const
{
	return level;
}


bool Logger::isAttached(const AppenderPtr appender) const
{
	return aai->isAttached(appender);
}

bool Logger::isTraceEnabled() const
{
	log4cxx::spi::LoggerRepositoryPtr rep = repository.lock();
	if (!rep || rep->isDisabled(Level::TRACE_INT))
	{
		return false;
	}

	return getEffectiveLevel()->toInt() <= Level::TRACE_INT;
}

bool Logger::isDebugEnabled() const
{
	log4cxx::spi::LoggerRepositoryPtr rep = repository.lock();
	if (!rep || rep->isDisabled(Level::DEBUG_INT))
	{
		return false;
	}

	return getEffectiveLevel()->toInt() <= Level::DEBUG_INT;
}

bool Logger::isEnabledFor(const LevelPtr& level1) const
{
	log4cxx::spi::LoggerRepositoryPtr rep = repository.lock();
	if (!rep || rep->isDisabled(level1->toInt()))
	{
		return false;
	}

	return level1->isGreaterOrEqual(getEffectiveLevel());
}


bool Logger::isInfoEnabled() const
{
	log4cxx::spi::LoggerRepositoryPtr rep = repository.lock();
	if (!rep || rep->isDisabled(Level::INFO_INT))
	{
		return false;
	}

	return getEffectiveLevel()->toInt() <= Level::INFO_INT;
}

bool Logger::isErrorEnabled() const
{
	log4cxx::spi::LoggerRepositoryPtr rep = repository.lock();
	if (!rep || rep->isDisabled(Level::ERROR_INT))
	{
		return false;
	}

	return getEffectiveLevel()->toInt() <= Level::ERROR_INT;
}

bool Logger::isWarnEnabled() const
{
	log4cxx::spi::LoggerRepositoryPtr rep = repository.lock();
	if (!rep || rep->isDisabled(Level::WARN_INT))
	{
		return false;
	}

	return getEffectiveLevel()->toInt() <= Level::WARN_INT;
}

bool Logger::isFatalEnabled() const
{
	log4cxx::spi::LoggerRepositoryPtr rep = repository.lock();
	if (!rep || rep->isDisabled(Level::FATAL_INT))
	{
		return false;
	}

	return getEffectiveLevel()->toInt() <= Level::FATAL_INT;
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



void Logger::l7dlog(const LevelPtr& level1, const LogString& key,
	const LocationInfo& location, const std::vector<LogString>& params) const
{
	log4cxx::spi::LoggerRepositoryPtr rep = repository.lock();
	if (!rep || rep->isDisabled(level1->toInt()))
	{
		return;
	}

	if (level1->isGreaterOrEqual(getEffectiveLevel()))
	{
		LogString pattern = getResourceBundleString(key);
		LogString msg;

		if (pattern.empty())
		{
			msg = key;
		}
		else
		{
			msg = StringHelper::format(pattern, params);
		}

		forcedLogLS(level1, msg, location);
	}
}

void Logger::l7dlog(const LevelPtr& level1, const std::string& key,
	const LocationInfo& location) const
{
	LOG4CXX_DECODE_CHAR(lkey, key);

	std::vector<LogString> values(0);
	l7dlog(level1, lkey, location, values);
}

void Logger::l7dlog(const LevelPtr& level1, const std::string& key,
	const LocationInfo& location, const std::string& val1) const
{
	LOG4CXX_DECODE_CHAR(lkey, key);
	LOG4CXX_DECODE_CHAR(lval1, val1);

	std::vector<LogString> values(1);
	values[0] = lval1;
	l7dlog(level1, lkey, location, values);
}

void Logger::l7dlog(const LevelPtr& level1, const std::string& key,
	const LocationInfo& location,
	const std::string& val1, const std::string& val2) const
{
	LOG4CXX_DECODE_CHAR(lkey, key);
	LOG4CXX_DECODE_CHAR(lval1, val1);
	LOG4CXX_DECODE_CHAR(lval2, val2);

	std::vector<LogString> values(2);
	values[0] = lval1;
	values[1] = lval2;
	l7dlog(level1, lkey, location, values);
}

void Logger::l7dlog(const LevelPtr& level1, const std::string& key,
	const LocationInfo& location,
	const std::string& val1, const std::string& val2, const std::string& val3) const
{
	LOG4CXX_DECODE_CHAR(lkey, key);
	LOG4CXX_DECODE_CHAR(lval1, val1);
	LOG4CXX_DECODE_CHAR(lval2, val2);
	LOG4CXX_DECODE_CHAR(lval3, val3);

	std::vector<LogString> values(3);
	values[0] = lval1;
	values[1] = lval2;
	values[2] = lval3;
	l7dlog(level1, lkey, location, values);
}



void Logger::removeAllAppenders()
{
	aai->removeAllAppenders();
}

void Logger::removeAppender(const AppenderPtr appender)
{
	aai->removeAppender(appender);
}

void Logger::removeAppender(const LogString& name1)
{
	aai->removeAppender(name1);
}

void Logger::setAdditivity(bool additive1)
{
	this->additive = additive1;
}

void Logger::setHierarchy(spi::LoggerRepositoryWeakPtr repository1)
{
	this->repository = repository1;
}

void Logger::setLevel(const LevelPtr level1)
{
	this->level = level1;
}



LoggerPtr Logger::getLogger(const std::string& name)
{
	return LogManager::getLogger(name);
}


LoggerPtr Logger::getLogger(const char* const name)
{
	return LogManager::getLogger(name);
}



LoggerPtr Logger::getRootLogger()
{
	return LogManager::getRootLogger();
}

LoggerPtr Logger::getLoggerLS(const LogString& name,
	const spi::LoggerFactoryPtr& factory)
{
	return LogManager::getLoggerLS(name, factory);
}

void Logger::getName(std::string& rv) const
{
	Transcoder::encode(name, rv);
}


void Logger::trace(const std::string& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isTraceEnabled())
	{
		forcedLog(log4cxx::Level::getTrace(), msg, location);
	}
}


void Logger::trace(const std::string& msg) const
{
	if (isTraceEnabled())
	{
		forcedLog(log4cxx::Level::getTrace(), msg);
	}
}

void Logger::debug(const std::string& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isDebugEnabled())
	{
		forcedLog(log4cxx::Level::getDebug(), msg, location);
	}
}

void Logger::debug(const std::string& msg) const
{
	if (isDebugEnabled())
	{
		forcedLog(log4cxx::Level::getDebug(), msg);
	}
}


void Logger::error(const std::string& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isErrorEnabled())
	{
		forcedLog(log4cxx::Level::getError(), msg, location);
	}
}


void Logger::error(const std::string& msg) const
{
	if (isErrorEnabled())
	{
		forcedLog(log4cxx::Level::getError(), msg);
	}
}

void Logger::fatal(const std::string& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isFatalEnabled())
	{
		forcedLog(log4cxx::Level::getFatal(), msg, location);
	}
}

void Logger::fatal(const std::string& msg) const
{
	if (isFatalEnabled())
	{
		forcedLog(log4cxx::Level::getFatal(), msg);
	}
}

void Logger::info(const std::string& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isInfoEnabled())
	{
		forcedLog(log4cxx::Level::getInfo(), msg, location);
	}
}

void Logger::info(const std::string& msg) const
{
	if (isInfoEnabled())
	{
		forcedLog(log4cxx::Level::getInfo(), msg);
	}
}

void Logger::log(const LevelPtr& level1, const std::string& message,
	const log4cxx::spi::LocationInfo& location) const
{
	if (isEnabledFor(level1))
	{
		forcedLog(level1, message, location);
	}
}

void Logger::log(const LevelPtr& level1, const std::string& message) const
{
	if (isEnabledFor(level1))
	{
		forcedLog(level1, message);
	}
}

void Logger::logLS(const LevelPtr& level1, const LogString& message,
	const log4cxx::spi::LocationInfo& location) const
{
	if (isEnabledFor(level1))
	{
		forcedLogLS(level1, message, location);
	}
}

void Logger::warn(const std::string& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isWarnEnabled())
	{
		forcedLog(log4cxx::Level::getWarn(), msg, location);
	}
}

void Logger::warn(const std::string& msg) const
{
	if (isWarnEnabled())
	{
		forcedLog(log4cxx::Level::getWarn(), msg);
	}
}

LoggerPtr Logger::getLoggerLS(const LogString& name)
{
	return LogManager::getLoggerLS(name);
}




#if LOG4CXX_WCHAR_T_API
void Logger::forcedLog(const LevelPtr& level1, const std::wstring& message,
	const LocationInfo& location) const
{
	Pool p;
	LOG4CXX_DECODE_WCHAR(msg, message);
	LoggingEventPtr event(new LoggingEvent(name, level1, msg, location));
	callAppenders(event, p);
}

void Logger::forcedLog(const LevelPtr& level1, const std::wstring& message) const
{
	Pool p;
	LOG4CXX_DECODE_WCHAR(msg, message);
	LoggingEventPtr event(new LoggingEvent(name, level1, msg,
			LocationInfo::getLocationUnavailable()));
	callAppenders(event, p);
}

void Logger::getName(std::wstring& rv) const
{
	Transcoder::encode(name, rv);
}

LoggerPtr Logger::getLogger(const std::wstring& name)
{
	return LogManager::getLogger(name);
}

LoggerPtr Logger::getLogger(const wchar_t* const name)
{
	return LogManager::getLogger(name);
}

void Logger::trace(const std::wstring& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isTraceEnabled())
	{
		forcedLog(log4cxx::Level::getTrace(), msg, location);
	}
}


void Logger::trace(const std::wstring& msg) const
{
	if (isTraceEnabled())
	{
		forcedLog(log4cxx::Level::getTrace(), msg);
	}
}

void Logger::debug(const std::wstring& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isDebugEnabled())
	{
		forcedLog(log4cxx::Level::getDebug(), msg, location);
	}
}

void Logger::debug(const std::wstring& msg) const
{
	if (isDebugEnabled())
	{
		forcedLog(log4cxx::Level::getDebug(), msg);
	}
}

void Logger::error(const std::wstring& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isErrorEnabled())
	{
		forcedLog(log4cxx::Level::getError(), msg, location);
	}
}

void Logger::error(const std::wstring& msg) const
{
	if (isErrorEnabled())
	{
		forcedLog(log4cxx::Level::getError(), msg);
	}
}

void Logger::fatal(const std::wstring& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isFatalEnabled())
	{
		forcedLog(log4cxx::Level::getFatal(), msg, location);
	}
}

void Logger::fatal(const std::wstring& msg) const
{
	if (isFatalEnabled())
	{
		forcedLog(log4cxx::Level::getFatal(), msg);
	}
}

void Logger::info(const std::wstring& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isInfoEnabled())
	{
		forcedLog(log4cxx::Level::getInfo(), msg, location);
	}
}

void Logger::info(const std::wstring& msg) const
{
	if (isInfoEnabled())
	{
		forcedLog(log4cxx::Level::getInfo(), msg);
	}
}

void Logger::log(const LevelPtr& level1, const std::wstring& message,
	const log4cxx::spi::LocationInfo& location) const
{
	if (isEnabledFor(level1))
	{
		forcedLog(level1, message, location);
	}
}

void Logger::log(const LevelPtr& level1, const std::wstring& message) const
{
	if (isEnabledFor(level1))
	{
		forcedLog(level1, message);
	}
}

void Logger::warn(const std::wstring& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isWarnEnabled())
	{
		forcedLog(log4cxx::Level::getWarn(), msg, location);
	}
}

void Logger::warn(const std::wstring& msg) const
{
	if (isWarnEnabled())
	{
		forcedLog(log4cxx::Level::getWarn(), msg);
	}
}

#endif


#if LOG4CXX_UNICHAR_API || LOG4CXX_CFSTRING_API
void Logger::forcedLog(const LevelPtr& level1, const std::basic_string<UniChar>& message,
	const LocationInfo& location) const
{
	Pool p;
	LOG4CXX_DECODE_UNICHAR(msg, message);
	LoggingEventPtr event(new LoggingEvent(name, level1, msg, location));
	callAppenders(event, p);
}

void Logger::forcedLog(const LevelPtr& level1, const std::basic_string<UniChar>& message) const
{
	Pool p;
	LOG4CXX_DECODE_UNICHAR(msg, message);
	LoggingEventPtr event(new LoggingEvent(name, level1, msg,
			LocationInfo::getLocationUnavailable()));
	callAppenders(event, p);
}
#endif

#if LOG4CXX_UNICHAR_API
void Logger::getName(std::basic_string<UniChar>& rv) const
{
	Transcoder::encode(name, rv);
}

LoggerPtr Logger::getLogger(const std::basic_string<UniChar>& name)
{
	return LogManager::getLogger(name);
}

void Logger::trace(const std::basic_string<UniChar>& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isTraceEnabled())
	{
		forcedLog(log4cxx::Level::getTrace(), msg, location);
	}
}


void Logger::trace(const std::basic_string<UniChar>& msg) const
{
	if (isTraceEnabled())
	{
		forcedLog(log4cxx::Level::getTrace(), msg);
	}
}

void Logger::debug(const std::basic_string<UniChar>& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isDebugEnabled())
	{
		forcedLog(log4cxx::Level::getDebug(), msg, location);
	}
}

void Logger::debug(const std::basic_string<UniChar>& msg) const
{
	if (isDebugEnabled())
	{
		forcedLog(log4cxx::Level::getDebug(), msg);
	}
}

void Logger::error(const std::basic_string<UniChar>& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isErrorEnabled())
	{
		forcedLog(log4cxx::Level::getError(), msg, location);
	}
}

void Logger::error(const std::basic_string<UniChar>& msg) const
{
	if (isErrorEnabled())
	{
		forcedLog(log4cxx::Level::getError(), msg);
	}
}

void Logger::fatal(const std::basic_string<UniChar>& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isFatalEnabled())
	{
		forcedLog(log4cxx::Level::getFatal(), msg, location);
	}
}

void Logger::fatal(const std::basic_string<UniChar>& msg) const
{
	if (isFatalEnabled())
	{
		forcedLog(log4cxx::Level::getFatal(), msg);
	}
}

void Logger::info(const std::basic_string<UniChar>& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isInfoEnabled())
	{
		forcedLog(log4cxx::Level::getInfo(), msg, location);
	}
}

void Logger::info(const std::basic_string<UniChar>& msg) const
{
	if (isInfoEnabled())
	{
		forcedLog(log4cxx::Level::getInfo(), msg);
	}
}

void Logger::log(const LevelPtr& level1, const std::basic_string<UniChar>& message,
	const log4cxx::spi::LocationInfo& location) const
{
	if (isEnabledFor(level1))
	{
		forcedLog(level1, message, location);
	}
}

void Logger::log(const LevelPtr& level1, const std::basic_string<UniChar>& message) const
{
	if (isEnabledFor(level1))
	{
		forcedLog(level1, message);
	}
}

void Logger::warn(const std::basic_string<UniChar>& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isWarnEnabled())
	{
		forcedLog(log4cxx::Level::getWarn(), msg, location);
	}
}

void Logger::warn(const std::basic_string<UniChar>& msg) const
{
	if (isWarnEnabled())
	{
		forcedLog(log4cxx::Level::getWarn(), msg);
	}
}

#endif


#if LOG4CXX_CFSTRING_API
void Logger::forcedLog(const LevelPtr& level1, const CFStringRef& message,
	const LocationInfo& location) const
{
	Pool p;
	LOG4CXX_DECODE_CFSTRING(msg, message);
	LoggingEventPtr event(new LoggingEvent(name, level1, msg, location));
	callAppenders(event, p);
}

void Logger::forcedLog(const LevelPtr& level1, const CFStringRef& message) const
{
	Pool p;
	LOG4CXX_DECODE_CFSTRING(msg, message);
	LoggingEventPtr event(new LoggingEvent(name, level1, msg,
			LocationInfo::getLocationUnavailable()));
	callAppenders(event, p);
}

void Logger::getName(CFStringRef& rv) const
{
	rv = Transcoder::encode(name);
}

LoggerPtr Logger::getLogger(const CFStringRef& name)
{
	return LogManager::getLogger(name);
}

void Logger::trace(const CFStringRef& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isTraceEnabled())
	{
		forcedLog(log4cxx::Level::getTrace(), msg, location);
	}
}


void Logger::trace(const CFStringRef& msg) const
{
	if (isTraceEnabled())
	{
		forcedLog(log4cxx::Level::getTrace(), msg);
	}
}

void Logger::debug(const CFStringRef& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isDebugEnabled())
	{
		forcedLog(log4cxx::Level::getDebug(), msg, location);
	}
}

void Logger::debug(const CFStringRef& msg) const
{
	if (isDebugEnabled())
	{
		forcedLog(log4cxx::Level::getDebug(), msg);
	}
}

void Logger::error(const CFStringRef& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isErrorEnabled())
	{
		forcedLog(log4cxx::Level::getError(), msg, location);
	}
}

void Logger::error(const CFStringRef& msg) const
{
	if (isErrorEnabled())
	{
		forcedLog(log4cxx::Level::getError(), msg);
	}
}

void Logger::fatal(const CFStringRef& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isFatalEnabled())
	{
		forcedLog(log4cxx::Level::getFatal(), msg, location);
	}
}

void Logger::fatal(const CFStringRef& msg) const
{
	if (isFatalEnabled())
	{
		forcedLog(log4cxx::Level::getFatal(), msg);
	}
}

void Logger::info(const CFStringRef& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isInfoEnabled())
	{
		forcedLog(log4cxx::Level::getInfo(), msg, location);
	}
}

void Logger::info(const CFStringRef& msg) const
{
	if (isInfoEnabled())
	{
		forcedLog(log4cxx::Level::getInfo(), msg);
	}
}

void Logger::log(const LevelPtr& level1, const CFStringRef& message,
	const log4cxx::spi::LocationInfo& location) const
{
	if (isEnabledFor(level1))
	{
		forcedLog(level1, message, location);
	}
}

void Logger::log(const LevelPtr& level1, const CFStringRef& message) const
{
	if (isEnabledFor(level1))
	{
		forcedLog(level1, message);
	}
}

void Logger::warn(const CFStringRef& msg, const log4cxx::spi::LocationInfo& location) const
{
	if (isWarnEnabled())
	{
		forcedLog(log4cxx::Level::getWarn(), msg, location);
	}
}

void Logger::warn(const CFStringRef& msg) const
{
	if (isWarnEnabled())
	{
		forcedLog(log4cxx::Level::getWarn(), msg);
	}
}

#endif


