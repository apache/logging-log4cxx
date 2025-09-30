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

#ifndef LOG4CXX_ASYNC_BUFFER_H
#define LOG4CXX_ASYNC_BUFFER_H

#include <log4cxx/helpers/messagebuffer.h>
#include <functional>
#include <vector>

namespace LOG4CXX_NS
{

namespace helpers
{

/**
 *   This class is used by the LOG4CXX2_INFO and similar
 *   macros to support insertion operators.
 *   The class is not intended for use outside of that context.
 */
class LOG4CXX_EXPORT AsyncBuffer
{
public:
	/** An empty buffer.
	*/
	AsyncBuffer();

	/** A new buffer with the content of \c other
	*/
	AsyncBuffer(AsyncBuffer&& other);

	/** Release resources.
	*/
	~AsyncBuffer();

	/** Append a function to this buffer that will convert \c value to text.
	 *   @param value must be copy-constructable or move-constructable
	 *   @return this buffer.
	 */
	template<typename T>
	AsyncBuffer& operator<<(const T& value)
	{
		append([value](MessageBuffer& msgBuf)
			{
				msgBuf << value;
			});
		return *this;
	}

	/**
	* Has no item been added to this?
	*/
	bool empty() const;

	/**
	* Add text version of buffered values to \c msg
	*/
	void renderMessage(helpers::MessageBuffer& msg);

	/**
	* Remove all message appenders
	*/
	void clear();

private:
	AsyncBuffer(const AsyncBuffer&) = delete;
	AsyncBuffer& operator=(const AsyncBuffer&) = delete;

	LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(Private, m_priv)
	using MessageBufferAppender = std::function<void(MessageBuffer&)>;

	/**
	 *   Append \c function to this buffer.
	 */
	void append(const MessageBufferAppender& f);
};

} // namespace helpers
} // namespace LOG4CXX_NS

/**
Add a new logging event containing \c message to attached appender(s) if \c logger is enabled for <code>INFO</code> events.

\usage
~~~{.cpp}
LOG4CXX2_INFO(m_log, surface->GetName()
	<< " successfully planned " << std::fixed << std::setprecision(1) << ((plannedArea  / (plannedArea + unplannedArea)) * 100.0) << "%"
	<< " planned area " << std::fixed << std::setprecision(4) << plannedArea << "m^2"
	<< " unplanned area " << unplannedArea << "m^2"
	<< " planned segments " << surface->GetSegmentPlanCount() << " of " << surface->GetSegmentCount()
	);
~~~

@param logger the logger that has the enabled status.
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload.
*/
#define LOG4CXX2_INFO(logger, message) do { \
		if (::LOG4CXX_NS::Logger::isInfoEnabledFor(logger)) {\
			::LOG4CXX_NS::helpers::AsyncBuffer buf;\
			logger->addInfoEvent(std::move(buf << message), LOG4CXX_LOCATION);\
		}} while (0)

#endif

