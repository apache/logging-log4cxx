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

#ifndef _LOG4CXX_PRIVATE_LAYOUT_PRIV_H
#define _LOG4CXX_PRIVATE_LAYOUT_PRIV_H

#include <log4cxx/logstring.h>

#include <limits>

namespace LOG4CXX_NS
{
namespace priv
{
	// Saturating doubling helper for layout size estimation.
	inline size_t doubledLayoutSize(size_t value)
	{
		const size_t maxSize = (std::numeric_limits<size_t>::max)();
		return value > maxSize / 2 ? maxSize : value * 2;
	}

	// Reserve only when the combined size fits within max_size().
	inline void reserveFormattedEvent(LogString& output, size_t fixedSize, size_t messageSize)
	{
		const size_t maxSize = output.max_size();
		if (messageSize <= maxSize && fixedSize <= maxSize - messageSize)
		{
			output.reserve(fixedSize + messageSize);
		}
	}
}
}

#endif // _LOG4CXX_PRIVATE_LAYOUT_PRIV_H
