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
#include <log4cxx/rolling/action.h>
#include <log4cxx/private/action_priv.h>
#include <log4cxx/helpers/loglog.h>
#include <mutex>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::rolling;
using namespace LOG4CXX_NS::helpers;

IMPLEMENT_LOG4CXX_OBJECT(Action)

Action::Action() :
	m_priv( std::make_unique<Action::ActionPrivate>() )
{
}

Action::Action( std::unique_ptr<ActionPrivate> priv ) :
	m_priv( std::move(priv) ) {}

Action::~Action()
{
}

void Action::run()
{
	std::lock_guard<std::mutex> lock(m_priv->mutex);

	if (!m_priv->closed)
	{
		try
		{
			execute();
		}
		catch (std::exception& ex)
		{
			helpers::LogLog::error(getName() + LOG4CXX_STR(" raised the following exception"), ex);
		}

		m_priv->complete = true;
		m_priv->closed = true;
	}
}

/**
 * {@inheritDoc}
 */
void Action::close()
{
	std::lock_guard<std::mutex> lock(m_priv->mutex);
	m_priv->closed = true;
}

/**
 * Tests if the action is complete.
 * @return true if action is complete.
 */
bool Action::isComplete() const
{
	return m_priv->complete;
}

LogString Action::getName() const
{
	return m_priv->actionName;
}

#if LOG4CXX_ABI_VERSION <= 15
bool Action::execute() const
{
	helpers::Pool p;
	return execute(p);
}

/**
 * Capture exception.
 *
 * @param ex exception.
 */
void Action::reportException(const std::exception& /* ex */)
{
}

void Action::run(helpers::Pool&)
{
	run();
}
#else
bool Action::execute(helpers::Pool&) const
{
	return execute();
}

#endif
