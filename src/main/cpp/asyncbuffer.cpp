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

#include <log4cxx/helpers/asyncbuffer.h>

namespace LOG4CXX_NS
{

namespace helpers
{

struct AsyncBuffer::Private
{
	std::vector<MessageBufferAppender> data;
};

/** An empty buffer.
*/
AsyncBuffer::AsyncBuffer()
{}

/** A new buffer with the content of \c other
*/
AsyncBuffer::AsyncBuffer(AsyncBuffer&& other)
	: m_priv(std::move(other.m_priv))
{
}

/** Release resources.
*/
AsyncBuffer::~AsyncBuffer()
{
}

/**
* Has no item been added to this?
*/
bool AsyncBuffer::empty() const { return !m_priv || m_priv->data.empty(); }

/**
* Add text version of buffered values to \c msg
*/
void AsyncBuffer::renderMessage(helpers::MessageBuffer& msg)
{
	if (m_priv)
		for (auto& renderer : m_priv->data)
			renderer(msg);
}

/**
* Remove all message appenders
*/
void AsyncBuffer::clear()
{
	if (m_priv)
		m_priv->data.clear();
}

/**
 *   Append \c function to this buffer.
 */
void AsyncBuffer::append(const MessageBufferAppender& f)
{
	if (!m_priv)
		m_priv = std::make_unique<Private>();
	m_priv->data.push_back(f);
}

} // namespace helpers
} // namespace LOG4CXX_NS

