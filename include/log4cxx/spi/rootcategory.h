/***************************************************************************
                          rootcategory.h  -  class RootCategory
                             -------------------
    begin                : jeu avr 17 2003
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

#ifndef _LOG4CXX_SPI_ROOT_CATEGORY_H
#define _LOG4CXX_SPI_ROOT_CATEGORY_H

#include <log4cxx/logger.h>

namespace log4cxx
{
	namespace spi
	{
        /**
        RootCategory sits at the top of the category hierachy. It is a
        regular category except that it provides several guarantees.

        <p>First, it cannot be assigned an <code>Level#OFF</code>
        level. Second, since root category cannot have a parent, the
        #getEffectiveLevel method always returns the value of the
        level field without walking the hierarchy.
        */
        class RootCategory : public Logger
		{
		public:
            /**
            The root category names itself as "root". However, the root
            category cannot be retrieved by name.
            */
            RootCategory(const Level& level);
 
            /**
            Return the assigned level value without walking the category
            hierarchy.
            */
            virtual const Level& getEffectiveLevel();

            /**
            Setting a null value to the level of the root category may have catastrophic
            results. We prevent this here.
			*/
            void setLevel(const Level& level);
		};
	}; // namespace spi
}; // namespace log4cxx

#endif //_LOG4CXX_SPI_ROOT_CATEGORY_H
