/***************************************************************************
                          optionconverter.h  -  class OptionConverter
                             -------------------
    begin                : mer avr 30 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#ifndef _LOG4CXX_HELPER_OPTION_CONVERTER_H
#define _LOG4CXX_HELPER_OPTION_CONVERTER_H

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/objectptr.h>

namespace log4cxx
{
	class Level;

	namespace helpers
	{
		class Properties;

		class Object;
		typedef ObjectPtrT<Object> ObjectPtr;

		class Class;

		class OptionConverter
		{
			static tstring DELIM_START;
			static TCHAR DELIM_STOP;
			static int DELIM_START_LEN;
			static int DELIM_STOP_LEN;

		/** OptionConverter is a static class. */
		private:
			OptionConverter() {}

		public:
			/**
			If <code>value</code> is "true", then <code>true</code> is
			returned. If <code>value</code> is "false", then
			<code>true</code> is returned. Otherwise, <code>default</code> is
			returned.

			<p>Case of value is unimportant.
			*/
			static bool toBoolean(const tstring& value, bool dEfault);
			static int toInt(const tstring& value, int dEfault);
			static long toFileSize(const tstring& value, long dEfault);
			static const Level& toLevel(const tstring& value,
				const Level& defaultValue);

			/**
     		Find the value corresponding to <code>key</code> in
     		<code>props</code>. Then perform variable substitution on the
     		found value.
			*/
			static tstring findAndSubst(const tstring& key, Properties& props);

			/**
			Perform variable substitution in string <code>val</code> from the
			values of keys found in the system propeties.

			<p>The variable substitution delimeters are <b>${</b> and <b>}</b>.

			<p>For example, if the System properties contains "key=value", then
			the call
			<pre>
			String s = OptionConverter.substituteVars("Value of key is ${key}.");
			</pre>

			will set the variable <code>s</code> to "Value of key is value.".

			<p>If no value could be found for the specified key, then the
			<code>props</code> parameter is searched, if the value could not
			be found there, then substitution defaults to the empty string.

			<p>For example, if system propeties contains no value for the key
			"inexistentKey", then the call

			<pre>
			String s = OptionConverter.subsVars("Value of inexistentKey is [${inexistentKey}]");
			</pre>
			will set <code>s</code> to "Value of inexistentKey is []"

			<p>An IllegalArgumentException is thrown if
			<code>val</code> contains a start delimeter "${" which is not
			balanced by a stop delimeter "}". </p>

			<p><b>Author</b> Avy Sharell</a></p>

			@param val The string on which variable substitution is performed.
			@throws IllegalArgumentException if <code>val</code> is malformed.
			*/
			static tstring substVars(const tstring& val, Properties& props);

			/**
			@param key The key to search for.
			@param def The default value to return.
			@return the string value of the system property, or the default
			value if there is no property with that key.
			*/
			static tstring getSystemProperty(const tstring& key, const tstring& def);

			/**
			Instantiate an object given a class name. Check that the
			<code>className</code> is a subclass of
			<code>superClass</code>. If that test fails or the object could
			not be instantiated, then <code>defaultValue</code> is returned.

			@param className The fully qualified class name of the object to instantiate.
			@param superClass The class to which the new object should belong.
			@param defaultValue The object to return in case of non-fulfillment
			*/
			static ObjectPtr instantiateByClassName(const tstring& className,
				const Class& superClass, ObjectPtr defaultValue);

			static ObjectPtr instantiateByKey(Properties& props,
				const tstring& key, const Class& superClass,
				ObjectPtr defaultValue);
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif //_LOG4CXX_HELPER_OPTION_CONVERTER_H

