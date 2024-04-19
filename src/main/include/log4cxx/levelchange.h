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

#ifndef LOG4CXX_LEVEL_CHANGE_HDR_
#define LOG4CXX_LEVEL_CHANGE_HDR_

#include <log4cxx/logmanager.h>
#include <log4cxx/logger.h>

namespace LOG4CXX_NS
{

/**
 * Changes a verbosity level for the instance variable's lifetime.

 * Create a LevelChange variable on the stack
 * to temporarily (e.g. for a single method)
 * increase the quantity of information logged.

 * Typically used to propagate the locally used logger's level (e.g. DEBUG or TRACE)
 * to another named (e.g. the name of the class of the method invoked next) logger.

 * The LevelChange variable does not need to be removed from the code (e.g. for a release build)
 * as it has no impact when the local and other logger point to the same level
 * (e.g. null_ptr, implying their level is inherited).
 */
 class LevelChange
{
	LoggerPtr m_otherCategory;
	LevelPtr m_savedLevel;
public: // ...structors
	/// Set \c otherCategory to \c level
	LevelChange(const LoggerPtr& otherCategory, const LevelPtr& level)
		: m_otherCategory(otherCategory)
		, m_savedLevel(otherCategory->getLevel())
	{
		m_otherCategory->setLevel(level);
	}
	/// Set \c otherCategory to the level of \c thisCategory
	LevelChange(const LoggerPtr& otherCategory, const LoggerPtr& thisCategory)
		: LevelChange(otherCategory, thisCategory->getLevel())
	{
	}
	/// Set the logger named \c otherCategory to \c level
	template <class StringType>
	LevelChange(const StringType& otherCategory, const LevelPtr& level)
		: LevelChange(LogManager::getLogger(otherCategory), level)
	{
	}
	/// Set the logger named \c otherCategory to the level of \c thisCategory
	template <class StringType>
	LevelChange(const StringType& otherCategory, const LoggerPtr& thisCategory)
		: LevelChange(LogManager::getLogger(otherCategory), thisCategory->getLevel())
	{
	}
	/// Restore the verbosity level of the other logger
	~LevelChange()
	{
		m_otherCategory->setLevel(m_savedLevel);
	}
private: // Prevent copies and assignment 
	LevelChange(const LevelChange&) = delete;
	LevelChange(LevelChange&&) = delete;
	LevelChange& operator=(const LevelChange&) = delete;
	LevelChange& operator=(LevelChange&&) = delete;
};

} // namespace LOG4CXX_NS

#endif // LOG4CXX_LEVEL_CHANGE_HDR_
