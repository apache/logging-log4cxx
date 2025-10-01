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
 *   This class is used by the LOG4CXX_INFO_ASYNC and similar
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
	 *   @param value type must be copy-constructable
	 *   @return this buffer.
	 */
	template<typename T>
	AsyncBuffer& operator<<(const T& value)
	{
		append([value](LogCharMessageBuffer& msgBuf)
			{
				msgBuf << value;
			});
		return *this;
	}

	/** Append a function to this buffer that will convert \c value to text.
	 *   @param value type must be move-constructable
	 *   @return this buffer.
	 */
	template<typename T>
	AsyncBuffer& operator<<(const T&& rvalue)
	{
		append([value = std::move(rvalue)](LogCharMessageBuffer& msgBuf)
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
	void renderMessage(LogCharMessageBuffer& msg);

	/**
	* Remove all message appenders
	*/
	void clear();

private:
	AsyncBuffer(const AsyncBuffer&) = delete;
	AsyncBuffer& operator=(const AsyncBuffer&) = delete;

	LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(Private, m_priv)
	using MessageBufferAppender = std::function<void(LogCharMessageBuffer&)>;

	/**
	 *   Append \c function to this buffer.
	 */
	void append(const MessageBufferAppender& f);
};

} // namespace helpers
} // namespace LOG4CXX_NS

/** @addtogroup LoggingMacros Logging macros
@{
*/

#if !defined(LOG4CXX_THRESHOLD) || LOG4CXX_THRESHOLD <= 10000
/**
Add a new logging event containing \c message to attached appender(s) if \c logger is enabled for <code>DEBUG</code> events.

\usage
~~~{.cpp}
LOG4CXX_DEBUG_ASYNC(m_log, "AddMesh:"
	<< " name " << meshName
	<< " type 0x" << std:: hex << traits.Type
	<< " materialName " << meshObject.GetMaterialName()
	<< " visible? " << traits.IsDefaultVisible
	<< " at " << obj->getBoundingBox().getCenter()
	<< " +/- " << obj->getBoundingBox().getHalfSize()
	);
~~~

@param logger the logger that has the enabled status.
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload.

*/
#define LOG4CXX_DEBUG_ASYNC(logger, message) do { \
		if (LOG4CXX_UNLIKELY(::LOG4CXX_NS::Logger::isDebugEnabledFor(logger))) {\
			::LOG4CXX_NS::helpers::AsyncBuffer buf; \
			logger->addDebugEvent(std::move(buf << message), LOG4CXX_LOCATION); }} while (0)
#else
#define LOG4CXX_DEBUG_ASYNC(logger, message)
#endif

#if !defined(LOG4CXX_THRESHOLD) || LOG4CXX_THRESHOLD <= 5000
/**
Add a new logging event containing \c message to attached appender(s) if \c logger is enabled for <code>TRACE</code> events.

\usage
~~~{.cpp}
    LOG4CXX_TRACE_ASYNC(m_log, "AddVertex:" << " at " << p << " n " << n << ' ' << color);
~~~

@param logger the logger that has the enabled status.
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload.
*/
#define LOG4CXX_TRACE_ASYNC(logger, message) do { \
		if (LOG4CXX_UNLIKELY(::LOG4CXX_NS::Logger::isTraceEnabledFor(logger))) {\
			::LOG4CXX_NS::helpers::AsyncBuffer buf; \
			logger->addTraceEvent(std::move(buf << message), LOG4CXX_LOCATION); }} while (0)
#else
#define LOG4CXX_TRACE_ASYNC(logger, message)
#endif

#if !defined(LOG4CXX_THRESHOLD) || LOG4CXX_THRESHOLD <= 20000
/**
Add a new logging event containing \c message to attached appender(s) if \c logger is enabled for <code>INFO</code> events.

\usage
~~~{.cpp}
LOG4CXX_INFO_ASYNC(m_log, surface->GetName()
	<< " successfully planned " << std::fixed << std::setprecision(1) << ((plannedArea  / (plannedArea + unplannedArea)) * 100.0) << "%"
	<< " planned area " << std::fixed << std::setprecision(4) << plannedArea << "m^2"
	<< " unplanned area " << unplannedArea << "m^2"
	<< " planned segments " << surface->GetSegmentPlanCount() << " of " << surface->GetSegmentCount()
	);
~~~

@param logger the logger that has the enabled status.
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload.
*/
#define LOG4CXX_INFO_ASYNC(logger, message) do { \
		if (::LOG4CXX_NS::Logger::isInfoEnabledFor(logger)) {\
			::LOG4CXX_NS::helpers::AsyncBuffer buf;\
			logger->addInfoEvent(std::move(buf << message), LOG4CXX_LOCATION);\
		}} while (0)

#endif

#else
#define LOG4CXX_INFO_ASYNC(logger, message)
#endif

#if !defined(LOG4CXX_THRESHOLD) || LOG4CXX_THRESHOLD <= 30000
/**
Add a new logging event containing \c message to attached appender(s) if \c logger is enabled for <code>WARN</code> events.

\usage
~~~{.cpp}
catch (const std::exception& ex)
{
    LOG4CXX_WARN_ASYNC(m_log, ex.what() << ": in " << m_task->GetParamFilePath());
}
~~~

@param logger the logger to be used.
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload.
*/
#define LOG4CXX_WARN_ASYNC(logger, message) do { \
		if (::LOG4CXX_NS::Logger::isWarnEnabledFor(logger)) {\
			::LOG4CXX_NS::helpers::AsyncBuffer buf; \
			logger->addWarnEvent(std::move(buf << message), LOG4CXX_LOCATION); }} while (0)
#else
#define LOG4CXX_WARN_ASYNC(logger, message)
#endif

#if !defined(LOG4CXX_THRESHOLD) || LOG4CXX_THRESHOLD <= 40000
/**
Add a new logging event containing \c message to attached appender(s) if \c logger is enabled for <code>ERROR</code> events.

\usage
~~~{.cpp}
catch (std::exception& ex)
{
	LOG4CXX_ERROR_ASYNC(m_log, ex.what() << " in AddScanData");
}
~~~

@param logger the logger to be used.
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload.
*/
#define LOG4CXX_ERROR_ASYNC(logger, message) do { \
		if (::LOG4CXX_NS::Logger::isErrorEnabledFor(logger)) {\
			::LOG4CXX_NS::helpers::AsyncBuffer buf; \
			logger->addErrorEvent(std::move(buf << message), LOG4CXX_LOCATION); }} while (0)

/**
If \c condition is not true, add a new logging event containing \c message to attached appender(s) if \c logger is enabled for <code>ERROR</code> events.

@param logger the logger to be used.
@param condition condition
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload.
*/
#define LOG4CXX_ASSERT_ASYNC(logger, condition, message) do { \
		if (!(condition) && ::LOG4CXX_NS::Logger::isErrorEnabledFor(logger)) {\
			::LOG4CXX_NS::helpers::AsyncBuffer buf; \
			LOG4CXX_STACKTRACE \
			logger->addErrorEvent(std::move(buf << message), LOG4CXX_LOCATION); }} while (0)

#else
#define LOG4CXX_ERROR_ASYNC(logger, message)
#define LOG4CXX_ASSERT_ASYNC(logger, condition, message)
#endif

#if !defined(LOG4CXX_THRESHOLD) || LOG4CXX_THRESHOLD <= 50000
/**
Add a new logging event containing \c message to attached appender(s) if \c logger is enabled for <code>FATAL</code> events.

\usage
~~~{.cpp}
LOG4CXX_FATAL_ASYNC(m_log, m_renderSystem->getName() << " is not supported");
LOG4CXX_FATAL_ASYNC(m_log, m_renderSystem->getName() << " is not supported");
~~~

@param logger the logger to be used.
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload.
*/
#define LOG4CXX_FATAL_ASYNC(logger, message) do { \
		if (::LOG4CXX_NS::Logger::isFatalEnabledFor(logger)) {\
			::LOG4CXX_NS::helpers::AsyncBuffer buf; \
			logger->addFatalEvent(std::move(buf << message), LOG4CXX_LOCATION); }} while (0)

#else
#define LOG4CXX_FATAL_ASYNC(logger, message)
#endif

/**@} Logging macro group */
