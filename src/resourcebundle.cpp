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

#include <log4cxx/helpers/resourcebundle.h>
#include <log4cxx/helpers/propertyresourcebundle.h>
#include <log4cxx/helpers/loader.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/helpers/transcoder.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(ResourceBundle)

ResourceBundlePtr ResourceBundle::getBundle(const LogString& baseName,
	const Locale& locale)
{
	LogString bundleName;
	PropertyResourceBundlePtr resourceBundle, previous;

	std::vector<LogString> bundlesNames;

	if (!locale.getVariant().empty())
	{
		bundlesNames.push_back(baseName + LOG4CXX_STR("_") +
			locale.getLanguage() + LOG4CXX_STR("_") +
			locale.getCountry() + LOG4CXX_STR("_") +
			locale.getVariant());
	}

	if (!locale.getCountry().empty())
	{
		bundlesNames.push_back(baseName + LOG4CXX_STR("_") +
				locale.getLanguage() + LOG4CXX_STR("_") +
				locale.getCountry());
	}

	if (!locale.getLanguage().empty())
	{
		bundlesNames.push_back(baseName + LOG4CXX_STR("_") +
					locale.getLanguage());
	}

	bundlesNames.push_back(baseName);
        Pool pool;

	for (std::vector<LogString>::iterator it = bundlesNames.begin();
		it != bundlesNames.end(); it++)
	{
#if 0
// TODO

                LogString bundleStream;
		bundleName = *it;

		PropertyResourceBundlePtr current;

		try
		{
			const Class& classObj = Loader::loadClass(bundleName);
			current = classObj.newInstance();
		}
		catch(ClassNotFoundException&)
		{
			current = 0;
		}

		if (current == 0)
		{
                        apr_size_t bytes = 0;
                        void* buf = Loader::getResourceAsStream(
                           bundleName + LOG4CXX_STR(".properties"),
                           &bytes, pool);
                        if (bytes == 0 || buf == NULL) {
                          continue;
                        }
                        log4cxx::helpers::Transcoder::decode(buf, bytes, pool, bundleStream);
		}

		try
		{
			current = new PropertyResourceBundle(bundleStream);
		}
		catch(Exception&)
		{
			throw;
		}

		bundleStream.erase(bundleStream.begin(), bundleStream.end());

		if (resourceBundle == 0)
		{
			resourceBundle = current;
			previous = current;
		}
		else
		{
			previous->setParent(current);
			previous = current;
		}
#endif
	}

	if (resourceBundle == 0)
	{
		throw MissingResourceException(
                      ((LogString) LOG4CXX_STR("Missing resource bundle ")) + baseName);
	}

	return resourceBundle;
}


