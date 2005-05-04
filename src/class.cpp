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

#include <log4cxx/helpers/class.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/object.h>
#include <map>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/private/log4cxx.h>

using namespace log4cxx;
using namespace log4cxx::helpers;



Class::Class() {
}

Class::~Class()
{
}

const LogString Class::toString() const
{
        return getName();
}

ObjectPtr Class::newInstance() const
{
        throw InstantiationException("Cannot create new instances of Class.");
#if LOG4CXX_RETURN_AFTER_THROW
        return 0;
#endif
}


Class::ClassMap& Class::getRegistry() {
    static ClassMap registry;
    return registry;
}

const Class& Class::forName(const LogString& className)
{
        LogString strippedClassName;
        LogString::size_type pos = className.find_last_of(LOG4CXX_STR('.'));
        if (pos != LogString::npos)
        {
                strippedClassName.assign(className.substr(pos + 1));
        }
        else
        {
                strippedClassName.assign(className);
        }

        const Class * clazz = getRegistry()[StringHelper::toLowerCase(strippedClassName)];

        if (clazz == 0)
        {
                throw ClassNotFoundException(className);
        }

        return *clazz;
}

bool Class::registerClass(const Class& newClass)
{
        getRegistry()[StringHelper::toLowerCase(newClass.getName())] = &newClass;
        return true;
}
