/***************************************************************************
                          class.cpp  -  class Class
                             -------------------
    begin                : mar avr 15 2003
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

#include <log4cxx/helpers/object.h>
#include <log4cxx/helpers/class.h>
#include <map>
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx::helpers;

typedef std::map<tstring, const Class *> classMap;
classMap * registry = 0;

class RegistryDestructor
{
public:
	~RegistryDestructor()
	{
		if (registry != 0)
			delete registry;
	}
};

Class::Class(const tstring& name) : name(name)
{
	registerClass(this);
}

const tstring& Class::toString() const
{
	return name;
}

ObjectPtr Class::newInstance() const
{
	throw InstantiationException();
	return 0;
}

const Class& Class::forName(const tstring& className)
{
	const Class * clazz = (*registry)[StringHelper::toLowerCase(className)];

	if (clazz == 0)
	{
		throw ClassNotFoundException();
	}

	return *clazz;
}

void Class::registerClass(const Class * newClass)
{
	if (newClass == 0)
	{
		return;
	}

	if (registry == 0)
	{
		registry = new classMap();
	}

	(*registry)[StringHelper::toLowerCase(newClass->toString())] = newClass;
}
