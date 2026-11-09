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

#ifndef _LOG4CXX_HELPER_OPTION_CONVERTER_H
#define _LOG4CXX_HELPER_OPTION_CONVERTER_H

#include <log4cxx/logstring.h>
#include <log4cxx/spi/configurator.h>

namespace LOG4CXX_NS
{
class Level;
class File;
typedef std::shared_ptr<Level> LevelPtr;


namespace helpers
{
class Properties;

class Class;

/** A convenience class to convert property values to specific types.*/
class LOG4CXX_EXPORT OptionConverter
{
		/** OptionConverter is a static class. */
	private:
		OptionConverter() {}

	public:
		static LogString convertSpecialChars(const LogString& s);

		/**
		 The boolean equivalent of \c value if it is not empty, otherwise \c defaultValue.

		If <code>value</code> is "true", then <code>true</code> is
		returned. If <code>value</code> is "false", then
		<code>true</code> is returned. Case of \c value is unimportant.

		@return  <code>defaultValue</code> if \c value is not "true" or "false", otherwise the boolean equivalent of \c value
		*/
		static bool toBoolean(const LogString& value, bool defaultValue);
		/**
		 The numeric equivalent of \c value if it is not empty, otherwise \c defaultValue.

		@return Zero if \c value does not begin with a valid integral number otherwise the numeric equivalent of \c value
		*/
		static int toInt(const LogString& value, int defaultValue);
		/**
		 The numeric equivalent of \c value if it is an integer in the range 0 - 2^63, otherwise \c defaultValue.

		 A suffix "KB", "MB" or "GB" after an integer value
		 converts the provided number respectively to kilobytes, megabytes
		 and gigabytes. For example, the value "10KB" will be interpreted as 10240.
		*/
		static size_t toFileSize(const LogString& value, size_t defaultValue);
		/**
		The Level indicated by \c value if recognised otherwise \c defaultValue.

		To be recognised, \c value must be one of "Trace", "Debug", "Info", "Warn", "Error", "Fatal", "Off", "All"
		or a custom level in which case it is of the form <code>{levelName}#{registeredClassName}</code>.

		<p>Case of \c value is unimportant.
		*/
		static LevelPtr toLevel(const LogString& value,
			const LevelPtr& defaultValue);

		/**
		Find the value corresponding to <code>key</code> in
		<code>props</code>. Then perform variable substitution on the
		found value.
		*/
		static LogString findAndSubst(const LogString& key, const Properties& props);

		/**
		Perform variable substitution in string <code>val</code> from the
		values of keys found in the system propeties.

		<p>The variable substitution delimeters are <b>${</b> and <b>}</b>.

		<p>For example, if the System properties contains "key=value", then
		the call
		~~~{.cpp}
		auto s = OptionConverter.substituteVars("Value of key is ${key}.");
		~~~

		will set the variable <code>s</code> to "Value of key is value.".

		<p>If no value could be found for the specified key, then the
		<code>props</code> parameter is searched, if the value could not
		be found there, then substitution defaults to the empty string.

		<p>For example, if system propeties contains no value for the key
		"inexistentKey", then the call

		~~~{.cpp}
		auto s = OptionConverter.subsVars("Value of inexistentKey is [${inexistentKey}]");
		~~~
		will set <code>s</code> to "Value of inexistentKey is []"

		<p>An IllegalArgumentException is thrown if
		<code>val</code> contains a start delimeter "${" which is not
		balanced by a stop delimeter "}". </p>

		@param val The string on which variable substitution is performed.
		@param props The properties from which variable substitution is performed.
		@throws IllegalArgumentException if <code>val</code> is malformed.
		*/
		static LogString substVars(const LogString& val, const Properties& props);

		/**
		 *  Gets the specified system property.
		@param key The key to search for.
		@param def The default value to return.
		@return the string value of the system property, or the default
		value if there is no property with that key.
		*/
		static LogString getSystemProperty(const LogString& key, const LogString& def);

		/**
		Instantiate an object given a class name.
		Returns \c defaultValue if the named class is not a registered class
		or the class does not inherit from \c superClass.

		@param className The registered name of the class to construct.
		@param superClass The class from which the new object must inherit.
		@param defaultValue The value to return in case of failure
		*/
		static ObjectPtr instantiateByClassName
			( const LogString& className
			, const Class&     superClass
			, const ObjectPtr& defaultValue
			);

		/**
		Instantiate an object using the value in \c props associated with \c key as a registered class name.
		Returns \c defaultValue if the named class is not a registered class
		or the class does not inherit from \c superClass.

		@param key The \c props entry whose value is the registered name of the class to construct.
		@param superClass The class from which the new object must inherit.
		@param defaultValue The value to return in case of failure
		*/
		static ObjectPtr instantiateByKey
			( const Properties& props
			, const LogString&  key
			, const Class&      superClass
			, const ObjectPtr&  defaultValue
			);

		/**
		Use the information in \c configFileName to configure Log4cxx.

		@param configFileName Holds the path of the configuration file.
		@param className The spi::Configurator subclass used to process \c configFileName.
		If empty, a registered class whose name ends with "Configurator" and
		whose spi::Configurator::isValid instance method
		returns <code>true</code> is used to process the configuration file.
		@param target Holds the configuration result
		@param millisecondDelay If greater than zero, the milliseconds to sleep
		between checking if <code>configFileName</code> has been modified
		and needs to be reloaded.
		*/
		static spi::ConfigurationStatus selectAndConfigure
			( const File&                     configFileName
			, const LogString&                className = {}
			, const spi::LoggerRepositoryPtr& target = {}
			, int                             millisecondDelay = 0
			);
};
}  // namespace helpers
} // namespace log4cxx

#endif //_LOG4CXX_HELPER_OPTION_CONVERTER_H

