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
#include <log4cxx/helpers/charsetencoder.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/threadutility.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/bytearrayoutputstream.h>
#include <log4cxx/helpers/outputstreamwriter.h>
#include <log4cxx/helpers/socketoutputstream.h>
#include <log4cxx/helpers/threadutility.h>
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

SocketAppenderSkeleton::SocketAppenderSkeleton(const helpers::InetAddressPtr& address, int port, int reconnectionDelay)
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
}

void SocketAppenderSkeleton::activateOptions(  )
{
	_priv->connect();
}

void SocketAppenderSkeleton::append( const spi::LoggingEventPtr& event )
{
	if (_priv->outputSink && _priv->layout)
	{
		LogString output;
		_priv->layout->format(output, event);

		try
		{
			_priv->outputSink->write(output);
			_priv->outputSink->flush();
		}
		catch (const std::exception& e)
		{
			_priv->outputSink.reset();
			helpers::LogLog::warn(LOG4CXX_STR("Detected problem with connection: "), e);

			if (getReconnectionDelay() > 0)
			{
				_priv->fireConnector();
			}
		}
	}
}



void SocketAppenderSkeleton::SocketAppenderSkeletonPriv::connect()
{
	if (this->address == 0)
	{
		LogLog::error(LogString(LOG4CXX_STR("No remote host is set for Appender named \"")) +
			this->name + LOG4CXX_STR("\"."));
	}
	else
	{
		this->shutdown();

		try
		{
			if (LogLog::isDebugEnabled())
			{
				LogString msg(LOG4CXX_STR("Connecting to [")
					+ this->address->toString() + LOG4CXX_STR(":"));
				StringHelper::toString(this->port, msg);
				msg += LOG4CXX_STR("].");
				LogLog::debug(msg);
			}
			this->setOutputSink(Socket::create(this->address, this->port, this->socketSubclass));
		}
		catch (const SocketException& e)
		{
			LogString msg = LOG4CXX_STR("Could not connect to [")
				+ this->address->toString() + LOG4CXX_STR(":");
			StringHelper::toString(this->port, msg);
			msg += LOG4CXX_STR("].");

			if (0 < this->reconnectionDelay)
				this->fireConnector(); // start the connector task
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
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("RECONNECTIONDELAY"), LOG4CXX_STR("reconnectiondelay")))
	{
		setReconnectionDelay(OptionConverter::toInt(value, getDefaultDelay()));
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("SOCKETSUBCLASS"), LOG4CXX_STR("socketsubclass")))
	{
		setSocketSubclass(value);
	}
	else
	{
		AppenderSkeleton::setOption(option, value);
	}
}

void SocketAppenderSkeleton::SocketAppenderSkeletonPriv::fireConnector()
{
	std::lock_guard<std::recursive_mutex> lock(this->mutex);
	if (this->taskName.empty())
	{
		this->taskName = this->name + LOG4CXX_STR(":")
			+ this->address->toString() + LOG4CXX_STR(":");
		StringHelper::toString(this->port, this->taskName);
	}
	if (!this->retryTask)
	{
		this->retryTask = std::make_shared<RetryTask>();
		this->retryTask->priv = this;
	}
	auto taskManager = ThreadUtility::instancePtr();
	if (!taskManager->value().hasPeriodicTask(this->taskName))
	{
		if (LogLog::isDebugEnabled())
		{
			LogString msg(LOG4CXX_STR("Waiting "));
			StringHelper::toString(this->reconnectionDelay, msg);
			msg += LOG4CXX_STR(" ms before retrying [")
				+ this->address->toString() + LOG4CXX_STR(":");
			StringHelper::toString(this->port, msg);
			msg += LOG4CXX_STR("].");
			LogLog::debug(msg);
		}
		auto retryTask = this->retryTask;
		taskManager->value().addPeriodicTask(this->taskName
			, [retryTask]() { retryTask->run(); }
			, std::chrono::milliseconds(this->reconnectionDelay)
			);
	}
	this->taskManager = taskManager;
}


void SocketAppenderSkeleton::SocketAppenderSkeletonPriv::retryConnect()
{
	if (this->closed)
	{
		if (auto pManager = this->taskManager.lock())
			pManager->value().removePeriodicTask(this->taskName);
	}
	else
	{
		try
		{
			if (LogLog::isDebugEnabled())
			{
				LogString msg(LOG4CXX_STR("Attempting connection to [")
					+ this->address->toString() + LOG4CXX_STR(":"));
				StringHelper::toString(this->port, msg);
				msg += LOG4CXX_STR("].");
				LogLog::debug(msg);
			}
			this->setOutputSink(Socket::create(this->address, this->port, this->socketSubclass));
			if (LogLog::isDebugEnabled())
			{
				LogString msg(LOG4CXX_STR("Connection established to [")
					+ this->address->toString() + LOG4CXX_STR(":"));
				StringHelper::toString(this->port, msg);
				msg += LOG4CXX_STR("].");
				LogLog::debug(msg);
			}
			if (auto pManager = this->taskManager.lock())
				pManager->value().removePeriodicTask(this->taskName);
			return;
		}
		catch (const ConnectException& e)
		{
			LogLog::warn(LOG4CXX_STR("Remote host ")
				+ this->address->toString()
				+ LOG4CXX_STR(" refused connection."), e);
		}
		catch (const IOException& e)
		{
			LogString msg(LOG4CXX_STR("Could not connect to [")
				+ this->address->toString() + LOG4CXX_STR(":"));
			StringHelper::toString(this->port, msg);
			msg += LOG4CXX_STR("].");
			LogLog::warn(msg, e);
		}

		if (0 < this->reconnectionDelay)
		{
			if (LogLog::isDebugEnabled())
			{
				LogString msg(LOG4CXX_STR("Waiting "));
				StringHelper::toString(this->reconnectionDelay, msg);
				msg += LOG4CXX_STR(" ms before retrying [")
					+ this->address->toString() + LOG4CXX_STR(":");
				StringHelper::toString(this->port, msg);
				msg += LOG4CXX_STR("].");
				LogLog::debug(msg);
			}
		}
	}
}

void SocketAppenderSkeleton::SocketAppenderSkeletonPriv::setOutputSink(const SocketPtr& socket)
{
	OutputStreamPtr os = std::make_shared<SocketOutputStream>(socket);
	auto charset = CharsetEncoder::getUTF8Encoder();
	// Serialize with AppenderSkeleton::doAppend
	std::lock_guard<std::recursive_mutex> lock(this->mutex);
	this->outputSink = std::make_shared<OutputStreamWriter>(os, charset);
}

void SocketAppenderSkeleton::SocketAppenderSkeletonPriv::shutdown()
{
	if (this->taskName.empty())
		;
	else if (auto pManager = this->taskManager.lock())
		pManager->value().removePeriodicTask(this->taskName);
	if (this->retryTask)
		this->retryTask->detach(); // Blocks until any in-flight retryConnect completes
	std::lock_guard<std::recursive_mutex> lock(this->mutex);
	if (this->outputSink)
	{
		try
		{
			this->outputSink->close();
			this->outputSink.reset();
		}
		catch (const std::exception&)
		{
		}
	}
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

void SocketAppenderSkeleton::setPort(int newValue)
{
	_priv->port = newValue;
}

int SocketAppenderSkeleton::getPort() const
{
	return _priv->port;
}

void SocketAppenderSkeleton::setReconnectionDelay(int millisecondDelay)
{
	_priv->reconnectionDelay = millisecondDelay;
	if (_priv->taskName.empty())
		return;
	auto pManager = _priv->taskManager.lock();
	if (pManager && pManager->value().hasPeriodicTask(_priv->taskName))
	{
		pManager->value().removePeriodicTask(_priv->taskName);
		if (0 < _priv->reconnectionDelay)
		{
			auto retryTask = _priv->retryTask;
			pManager->value().addPeriodicTask(_priv->taskName
				, [retryTask]() { retryTask->run(); }
				, std::chrono::milliseconds(_priv->reconnectionDelay)
				);
		}
	}
}

int SocketAppenderSkeleton::getReconnectionDelay() const
{
	return _priv->reconnectionDelay;
}

void SocketAppenderSkeleton::setSocketSubclass(const LogString& newValue)
{
	_priv->socketSubclass = newValue;
}

const LogString& SocketAppenderSkeleton::getSocketSubclass() const
{
	return _priv->socketSubclass;
}
