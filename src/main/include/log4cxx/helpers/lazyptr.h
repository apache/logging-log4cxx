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

#ifndef _LOG4CXX_HELPERS_LAZY_PTR_H
#define _LOG4CXX_HELPERS_LAZY_PTR_H
#include <atomic>
#include <memory>
#include <utility>

namespace LOG4CXX_NS { namespace helpers
{

/// A create-on-first-use smart pointer
template <typename T>
class LazyPtr
{
private:
	std::atomic<T*> m_ptr{nullptr};

public: // ...structors
	LazyPtr() = default;

	// Clean up allocated resource on destruction
	~LazyPtr()
	{
		delete m_ptr.load(std::memory_order_relaxed);
	}

	// Prevent copying to avoid double-free errors
	LazyPtr(const LazyPtr&) = delete;
	LazyPtr& operator=(const LazyPtr&) = delete;

	// Allow moving
	LazyPtr(LazyPtr&& other) noexcept
		: m_ptr(other.m_ptr.exchange(nullptr, std::memory_order_relaxed))
	{}

public: // Operators
	// Allow assignment
	LazyPtr& operator=(LazyPtr&& other) noexcept
	{
		if (this != &other)
		{
			delete m_ptr.load(std::memory_order_relaxed);
			m_ptr.store(other.m_ptr.exchange(nullptr, std::memory_order_relaxed),
					   std::memory_order_relaxed);
		}
		return *this;
	}

	// Lazy initialization & dereference
	T& operator*() { return *get_or_throw(); }

	// Lazy initialization
	T* operator->()	{ return get_or_throw(); }

	// Explicit bool conversion
	explicit operator bool() const noexcept
	{
		return m_ptr.load(std::memory_order_relaxed) != nullptr;
	}

	// The raw pointer value
	T* get_ptr() const noexcept
	{
		return m_ptr.load(std::memory_order_relaxed);
	}

private: // Modifiers
	// Lazily initialize if required
	T* get_or_throw()
	{
		T* p = m_ptr.load(std::memory_order_relaxed);
		if (!p)
		{
			auto* new_p = new T();
			if (!m_ptr.compare_exchange_strong(p, new_p
				, std::memory_order_relaxed
				, std::memory_order_relaxed
				)
			   )
			{
				delete new_p; // Lost the race
			}
			else
			{
				p = new_p;
			}
		}
		return p;
	}
};

} } // namespace LOG4CXX_NS::helpers

#endif // _LOG4CXX_HELPERS_LAZY_PTR_H
