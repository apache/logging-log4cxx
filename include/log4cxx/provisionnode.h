/***************************************************************************
                          provisionnode.h  -  class ProvisionNode
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

#ifndef _LOG4CXX_PROVISION_NODE_H
#define _LOG4CXX_PROVISION_NODE_H

#include <vector>
#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/logger.h>

namespace log4cxx
{
    class Logger;
    typedef helpers::ObjectPtrT<Logger> LoggerPtr;

    class ProvisionNode : public std::vector<LoggerPtr>
    {
    public:
		ProvisionNode(LoggerPtr logger)
		{
			push_back(logger);
		}
    }; // class LogManager
}; // namespace log4cxx

#endif //_LOG4CXX_PROVISION_NODE_H
