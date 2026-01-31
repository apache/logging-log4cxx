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

#define __STDC_CONSTANT_MACROS
#include <log4cxx/net/socketappenderskeleton.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/threadutility.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/bytearrayoutputstream.h>
#include <log4cxx/helpers/threadutility.h>
#include <log4cxx/private/appenderskeleton_priv.h>
#include <log4cxx/private/socketappenderskeleton_priv.h>
#include <functional>
#include <chrono>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::net;

#define _priv static_cast<SocketAppenderSkeletonPriv*>(m_priv.get())

SocketAppenderSkeleton::SocketAppenderSkeleton(int defaultPort, int reconnectionDelay)
	: AppenderSkeleton(std::make_unique<SocketAppenderSkeletonPriv>(defaultPort, reconnectionDelay))
{
}

SocketAppenderSkeleton::SocketAppenderSkeleton(helpers::InetAddressPtr address, int port, int reconnectionDelay)
	: AppenderSkeleton(std::make_unique<SocketAppenderSkeletonPriv>(address, port, reconnectionDelay))
{
}

SocketAppenderSkeleton::SocketAppenderSkeleton(const LogString& host, int port, int reconnectionDelay)
	: AppenderSkeleton(std::make_unique<SocketAppenderSkeletonPriv>(host, port, reconnectionDelay))
{
}

SocketAppenderSkeleton::SocketAppenderSkeleton(std::unique_ptr<SocketAppenderSkeletonPriv> priv)
	:  AppenderSkeleton (std::move(priv))
{
}

SocketAppenderSkeleton::~SocketAppenderSkeleton()
{
	finalize();
}

void SocketAppenderSkeleton::activateOptions()
{
    AppenderSkeleton::activateOptions();
	connect(p);
}

void SocketAppenderSkeleton::close()
{
	_priv->stopMonitor();
    cleanUp();
}

void SocketAppenderSkeleton::connect()
{
	if (_priv->address == 0)
	{
		LogLog::error(LogString(LOG4CXX_STR("No remote host is set for Appender named \"")) +
			_priv->name + LOG4CXX_STR("\"."));
	}
	else
	{
		cleanUp(p);

		try
		{
			if (LogLog::isDebugEnabled())
			{
				LogString msg(LOG4CXX_STR("Connecting to [")
					+ _priv->address->toString() + LOG4CXX_STR(":"));
                StringHelper::toString(_priv->port, msg);
				msg += LOG4CXX_STR("].");
				LogLog::debug(msg);
			}
			SocketPtr socket = Socket::create(_priv->address, _priv->port);
			setSocket(socket, p);
		}
		catch (SocketException& e)
		{
			LogString msg = LOG4CXX_STR("Could not connect to [")
				+ _priv->address->toString() + LOG4CXX_STR(":");
			StringHelper::toString(_priv->port, p, msg);
			msg += LOG4CXX_STR("].");

			fireConnector(); // fire the connector thread
			LogLog::warn(msg, e);
		}
	}
}

void SocketAppenderSkeleton::setOption(const LogString& option, const LogString& value)
{
	if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("REMOTEHOST"), LOG4CXX_STR("remotehost")))
	{
		setRemoteHost(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("PORT"), LOG4CXX_STR("port")))
	{
		setPort(OptionConverter::toInt(value, getDefaultPort()));
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("LOCATIONINFO"), LOG4CXX_STR("locationinfo")))
	{
		setLocationInfo(OptionConverter::toBoolean(value, false));
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("RECONNECTIONDELAY"), LOG4CXX_STR("reconnectiondelay")))
	{
		setReconnectionDelay(OptionConverter::toInt(value, getDefaultDelay()));
	}
	else
	{
		AppenderSkeleton::setOption(option, value);
	}
}

void SocketAppenderSkeleton::fireConnector()
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
    if (_priv->taskName.empty())
    {
        _priv->taskName = _priv->name + LOG4CXX_STR(":")
            + _priv->address->toString() + LOG4CXX_STR(":");
        StringHelper::toString(_priv->port, _priv->taskName);
    }
    auto taskManager = ThreadUtility::instancePtr();
    if (!taskManager->value().hasPeriodicTask(_priv->taskName))
    {
        if (LogLog::isDebugEnabled())
        {
            LogString msg(LOG4CXX_STR("Waiting "));
            StringHelper::toString(_priv->reconnectionDelay, msg);
            msg += LOG4CXX_STR(" ms before retrying [")
                + _priv->address->toString() + LOG4CXX_STR(":");
            StringHelper::toString(_priv->port, msg);
            msg += LOG4CXX_STR("].");
            LogLog::debug(msg);
        }
        taskManager->value().addPeriodicTask(_priv->taskName
            , std::bind(&SocketAppenderSkeleton::retryConnect, this)
            , std::chrono::milliseconds(_priv->reconnectionDelay)
            );
    }
    _priv->taskManager = taskManager;
}

void SocketAppenderSkeleton::retryConnect()
{
	if (is_closed())
	{
		if (auto pManager = _priv->taskManager.lock())
			pManager->value().removePeriodicTask(_priv->taskName);
	}
	else
    {
		SocketPtr socket;
		try
		{
			if (LogLog::isDebugEnabled())
			{
				LogString msg(LOG4CXX_STR("Attempting connection to [")
					+ _priv->address->toString() + LOG4CXX_STR(":"));
                StringHelper::toString(_priv->port, msg);
				msg += LOG4CXX_STR("].");
				LogLog::debug(msg);
			}
			socket = Socket::create(_priv->address, _priv->port);
            setSocket(socket);
			if (LogLog::isDebugEnabled())
			{
				LogString msg(LOG4CXX_STR("Connection established to [")
					+ _priv->address->toString() + LOG4CXX_STR(":"));
                StringHelper::toString(_priv->port, msg);
				msg += LOG4CXX_STR("].");
				LogLog::debug(msg);
			}
			if (auto pManager = _priv->taskManager.lock())
				pManager->value().removePeriodicTask(_priv->taskName);
			return;
		}
		catch (ConnectException& e)
		{
			LogLog::warn(LOG4CXX_STR("Remote host ")
				+ _priv->address->toString()
				+ LOG4CXX_STR(" refused connection."), e);
		}
		catch (IOException& e)
		{
			LogString msg(LOG4CXX_STR("Could not connect to [")
				+ _priv->address->toString() + LOG4CXX_STR(":"));
            StringHelper::toString(_priv->port, msg);
			msg += LOG4CXX_STR("].");
			LogLog::warn(msg, e);
		}

		if (_priv->reconnectionDelay > 0)
		{
			if (LogLog::isDebugEnabled())
			{
				LogString msg(LOG4CXX_STR("Waiting "));
                StringHelper::toString(_priv->reconnectionDelay, msg);
				msg += LOG4CXX_STR(" ms before retrying [")
					+ _priv->address->toString() + LOG4CXX_STR(":");
                StringHelper::toString(_priv->port, msg);
				msg += LOG4CXX_STR("].");
				LogLog::debug(msg);
			}
		}
	}
}

void SocketAppenderSkeleton::SocketAppenderSkeletonPriv::stopMonitor()
{
	this->closed = true;
	if (this->taskName.empty())
		;
	else if (auto pManager = this->taskManager.lock())
		pManager->value().removePeriodicTask(this->taskName);
}

bool SocketAppenderSkeleton::is_closed()
{
	return _priv->closed;
}

void SocketAppenderSkeleton::setRemoteHost(const LogString& host)
{
	_priv->address = helpers::InetAddress::getByName(host);
	_priv->remoteHost.assign(host);
}

const LogString& SocketAppenderSkeleton::getRemoteHost() const
{
	return _priv->remoteHost;
}

void SocketAppenderSkeleton::setPort(int port1)
{
	_priv->port = port1;
}

int SocketAppenderSkeleton::getPort() const
{
	return _priv->port;
}

void SocketAppenderSkeleton::setLocationInfo(bool locationInfo1)
{
	_priv->locationInfo = locationInfo1;
}

bool SocketAppenderSkeleton::getLocationInfo() const
{
	return _priv->locationInfo;
}

void SocketAppenderSkeleton::setReconnectionDelay(int reconnectionDelay1)
{
	_priv->reconnectionDelay = reconnectionDelay1;
	if (_priv->taskName.empty())
		return;
	auto pManager = _priv->taskManager.lock();
	if (pManager && pManager->value().hasPeriodicTask(_priv->taskName))
	{
		pManager->value().removePeriodicTask(_priv->taskName);
		pManager->value().addPeriodicTask(_priv->taskName
			, std::bind(&SocketAppenderSkeleton::retryConnect, this)
			, std::chrono::milliseconds(_priv->reconnectionDelay)
			);
	}
}

int SocketAppenderSkeleton::getReconnectionDelay() const
{
	return _priv->reconnectionDelay;
}
