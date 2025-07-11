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
#include <log4cxx/spi/loggerfactory.h>
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/helpers/optionconverter.h>
#include <algorithm>
#include <ctype.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/exception.h>
#include <stdlib.h>
#include <log4cxx/helpers/properties.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/object.h>
#include <log4cxx/helpers/class.h>
#include <log4cxx/helpers/loader.h>
#include <log4cxx/helpers/system.h>
#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/file.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/logmanager.h>
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/helpers/aprinitializer.h>
#include <log4cxx/helpers/filewatchdog.h>
#include <log4cxx/helpers/singletonholder.h>

namespace LOG4CXX_NS
{

class ConfiguratorWatchdog  : public helpers::FileWatchdog
{
	spi::ConfiguratorPtr m_config;
	public:
    ConfiguratorWatchdog(const spi::ConfiguratorPtr& config, const File& filename)
        : helpers::FileWatchdog(filename)
        , m_config(config)
    {
    }

    /**
    Call PropertyConfigurator#doConfigure(const String& configFileName,
    const spi::LoggerRepositoryPtr& hierarchy) with the
    <code>filename</code> to reconfigure log4cxx.
    */
    void doOnChange() override
    {
        m_config->doConfigure(file(), LogManager::getLoggerRepository());
    }

	static void startWatching(const spi::ConfiguratorPtr& config, const File& filename, long delay)
	{
		using WatchdogHolder = helpers::SingletonHolder<ConfiguratorWatchdog>;
		auto pHolder = helpers::APRInitializer::getOrAddUnique<WatchdogHolder>
			( [&config, &filename]() -> helpers::ObjectPtr
				{ return std::make_shared<WatchdogHolder>(config, filename); }
			);
		auto& dog = pHolder->value();
		dog.m_config = config;
		dog.setFile(filename);
		dog.setDelay(delay);
		dog.start();
	}
};

}

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::spi;


LogString OptionConverter::convertSpecialChars(const LogString& s)
{
	logchar c;
	LogString sbuf;

	LogString::const_iterator i = s.begin();

	while (i != s.end())
	{
		c = *i++;

		if (i != s.end() && c == 0x5C /* '\\' */)
		{
			c =  *i++;

			switch (c)
			{
				case 0x6E: //'n'
					c = 0x0A;
					break;

				case 0x72: //'r'
					c = 0x0D;
					break;

				case 0x74: //'t'
					c = 0x09;
					break;

				case 0x66: //'f'
					c = 0x0C;
					break;

				default:
					break;
			}
		}

		sbuf.append(1, c);
	}

	return sbuf;
}


bool OptionConverter::toBoolean(const LogString& value, bool dEfault)
{
	if (value.length() >= 4)
	{
		if (StringHelper::equalsIgnoreCase(value.substr(0, 4),
				LOG4CXX_STR("TRUE"), LOG4CXX_STR("true")))
		{
			return true;
		}
	}

	if (dEfault && value.length() >= 5)
	{
		if (StringHelper::equalsIgnoreCase(value.substr(0, 5),
				LOG4CXX_STR("FALSE"), LOG4CXX_STR("false")))
		{
			return false;
		}
	}

	return dEfault;
}

int OptionConverter::toInt(const LogString& value, int dEfault)
{
	LogString trimmed(StringHelper::trim(value));

	if (trimmed.empty())
	{
		return dEfault;
	}

	LOG4CXX_ENCODE_CHAR(cvalue, trimmed);

	return (int) atol(cvalue.c_str());
}

long OptionConverter::toFileSize(const LogString& s, long dEfault)
{
	if (s.empty())
	{
		return dEfault;
	}

	size_t index = s.find_first_of(LOG4CXX_STR("bB"));

	if (index != LogString::npos && index > 0)
	{
		long multiplier = 1;
		index--;

		if (s[index] == 0x6B /* 'k' */ || s[index] == 0x4B /* 'K' */)
		{
			multiplier = 1024;
		}
		else if (s[index] == 0x6D /* 'm' */ || s[index] == 0x4D /* 'M' */)
		{
			multiplier = 1024 * 1024;
		}
		else if (s[index] == 0x67 /* 'g'*/ || s[index] == 0x47 /* 'G' */)
		{
			multiplier = 1024 * 1024 * 1024;
		}

		return toInt(s.substr(0, index), 1) * multiplier;
	}

	return toInt(s, 1);
}

LogString OptionConverter::findAndSubst(const LogString& key, Properties& props)
{
	LogString value(props.getProperty(key));

	if (value.empty())
	{
		return value;
	}

	try
	{
		return substVars(value, props);
	}
	catch (IllegalArgumentException& e)
	{
		LogLog::error(((LogString) LOG4CXX_STR("Bad option value ["))
			+ value + LOG4CXX_STR("]."), e);
		return value;
	}
}

LogString OptionConverter::substVars(const LogString& val, Properties& props)
{
	LogString sbuf;
	const logchar delimStartArray[] = { 0x24, 0x7B, 0 };
	const LogString delimStart(delimStartArray);
	const logchar delimStop = 0x7D; // '}';
	const size_t DELIM_START_LEN = 2;
	const size_t DELIM_STOP_LEN = 1;

	size_t i = 0;

	while (true)
	{
		size_t j = val.find(delimStart, i);

		if (j == val.npos)
		{
			// no more variables
			if (i == 0)
			{
				// this is a simple string
				return val;
			}
			else
			{
				// add the tail string which contails no variables and return the result.
				sbuf.append(val.substr(i, val.length() - i));
				return sbuf;
			}
		}
		else
		{
			sbuf.append(val.substr(i, j - i));
			size_t k = val.find(delimStop, j);

			if (k == val.npos)
			{
				LogString msg(1, (logchar) 0x22 /* '\"' */);
				msg.append(val);
				msg.append(LOG4CXX_STR("\" has no closing brace. Opening brace at position "));
				Pool p;
				StringHelper::toString(j, p, msg);
				msg.append(1, (logchar) 0x2E /* '.' */);
				throw IllegalArgumentException(msg);
			}
			else
			{
				j += DELIM_START_LEN;
				LogString key = val.substr(j, k - j);
				// first try in System properties
				LogString replacement(getSystemProperty(key, LogString()));

				// then try props parameter
				if (replacement.empty())
				{
					replacement = props.getProperty(key);
				}

				if (!replacement.empty())
				{
					// Do variable substitution on the replacement string
					// such that we can solve "Hello ${x2}" as "Hello p1"
					// the where the properties are
					// x1=p1
					// x2=${x1}
					LogString recursiveReplacement = substVars(replacement, props);
					sbuf.append(recursiveReplacement);
				}

				i = k + DELIM_STOP_LEN;
			}
		}
	}
}

LogString OptionConverter::getSystemProperty(const LogString& key, const LogString& def)
{
	if (!key.empty())
	{
		LogString value(System::getProperty(key));

		if (!value.empty())
		{
			return value;
		}
	}

	return def;
}

LevelPtr OptionConverter::toLevel(const LogString& value,
	const LevelPtr& defaultValue)
{
	size_t hashIndex = value.find(LOG4CXX_STR("#"));

	if (hashIndex == LogString::npos)
	{
		if (value.empty())
		{
			return defaultValue;
		}
		else
		{
			if (LogLog::isDebugEnabled())
			{
				LogLog::debug(
					((LogString) LOG4CXX_STR("OptionConverter::toLevel: no class name specified, level=["))
					+ value
					+ LOG4CXX_STR("]"));
			}
			// no class name specified : use standard Level class
			return Level::toLevelLS(value, defaultValue);
		}
	}

	LogString clazz = value.substr(hashIndex + 1);
	LogString levelName = value.substr(0, hashIndex);
	if (LogLog::isDebugEnabled())
	{
		LogLog::debug(LOG4CXX_STR("OptionConverter::toLevel: class=[")
		+ clazz + LOG4CXX_STR("], level=[")
		+ levelName + LOG4CXX_STR("]")
		);
	}

	// This is degenerate case but you never know.
	if (levelName.empty())
	{
		return Level::toLevelLS(value, defaultValue);
	}

	try
	{
		// Note: the dynamic_cast could fail across DLL boundaries.
		// However, without the dynamic_cast a poorly formed XML file
		// could attempt to load an invalid class as a filter, causing
		// a crash.  If it can't be converted, a std::bad_cast should be
		// thrown(and caught by the exception handler below)
		const Level::LevelClass& levelClass =
			dynamic_cast<const Level::LevelClass&>(Loader::loadClass(clazz));
		return levelClass.toLevel(levelName);
	}
	catch (ClassNotFoundException&)
	{
		LogLog::warn(((LogString) LOG4CXX_STR("custom level class ["))
			+ clazz + LOG4CXX_STR("] not found."));
	}
	catch (Exception& oops)
	{
		LogLog::warn(
			LOG4CXX_STR("class [") + clazz + LOG4CXX_STR("], level [") + levelName +
			LOG4CXX_STR("] conversion) failed."), oops);
	}
	catch(const std::bad_cast&)
	{
		LogLog::warn(
			LOG4CXX_STR("class [") + clazz + LOG4CXX_STR("] unable to be converted to "
			"Level::LevelClass"));
	}
	catch (...)
	{
		LogLog::warn(
			LOG4CXX_STR("class [") + clazz + LOG4CXX_STR("], level [") + levelName +
			LOG4CXX_STR("] conversion) failed."));
	}

	return defaultValue;
}


ObjectPtr OptionConverter::instantiateByKey(Properties& props, const LogString& key,
	const Class& superClass, const ObjectPtr& defaultValue)
{
	// Get the value of the property in string form
	LogString className(findAndSubst(key, props));

	if (className.empty())
	{
		LogLog::error(
			((LogString) LOG4CXX_STR("Could not find value for key ")) + key);
		return defaultValue;
	}

	// Trim className to avoid trailing spaces that cause problems.
	return OptionConverter::instantiateByClassName(
			StringHelper::trim(className), superClass, defaultValue);
}

ObjectPtr OptionConverter::instantiateByClassName(const LogString& className,
	const Class& superClass, const ObjectPtr& defaultValue)
{
	if (!className.empty())
	{
		try
		{
			const Class& classObj = Loader::loadClass(className);
			ObjectPtr newObject =  ObjectPtr(classObj.newInstance());

			if (!newObject->instanceof(superClass))
			{
				return defaultValue;
			}

			return newObject;
		}
		catch (Exception& e)
		{
			LogLog::error(LOG4CXX_STR("Could not instantiate class [") +
				className + LOG4CXX_STR("]."), e);
		}
	}

	return defaultValue;
}

void OptionConverter::selectAndConfigure(const File& configFileName,
	const LogString& _clazz, spi::LoggerRepositoryPtr hierarchy, int delay)
{
	ConfiguratorPtr configurator;
	LogString clazz = _clazz;

	LogString filename(configFileName.getPath());

#if LOG4CXX_HAS_DOMCONFIGURATOR
	if (clazz.empty()
		&& filename.length() > 4
		&& StringHelper::equalsIgnoreCase(
			filename.substr(filename.length() - 4),
			LOG4CXX_STR(".XML"), LOG4CXX_STR(".xml")))
	{
		clazz = LOG4CXX_NS::xml::DOMConfigurator::getStaticClass().getName();
	}
#endif

	if (!clazz.empty())
	{
		if (LogLog::isDebugEnabled())
			LogLog::debug(LOG4CXX_STR("Preferred configurator class: ") + clazz);
		const Class& clazzObj = Loader::loadClass(clazz);
		ObjectPtr obj = ObjectPtr(clazzObj.newInstance());
		configurator = LOG4CXX_NS::cast<Configurator>(obj);

		if (configurator == 0)
		{
			LogLog::error(LOG4CXX_STR("Could not instantiate configurator [")
				+ clazz + LOG4CXX_STR("]."));
			return;
		}
	}
	else
	{
		configurator = std::make_shared<PropertyConfigurator>();
	}

	if (0 < delay)
		ConfiguratorWatchdog::startWatching(configurator, configFileName, delay);
	else
		configurator->doConfigure(configFileName, hierarchy);
}
