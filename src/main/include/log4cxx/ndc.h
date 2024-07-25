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

#ifndef _LOG4CXX_NDC_H
#define _LOG4CXX_NDC_H

#include <log4cxx/log4cxx.h>
#include <log4cxx/logstring.h>
#include <stack>

namespace LOG4CXX_NS
{

/**
A <em>Nested Diagnostic Context</em>, or #NDC in short, is an instrument
to distinguish interleaved log output from different sources.
Log output is typically interleaved when a server handles multiple
clients near-simultaneously.
Interleaved log output can still be meaningful if each log entry
from different contexts have a distinctive stamp.
This is where contexts come into play.

#NDC provides a constructor and destructor which simply call the #push and
#pop methods, allowing for automatic cleanup when the current scope ends.

#NDC operations such as #push, #pop, #clear and #remove
affect only logging events emitted in the <em>calling</em> thread.
The contexts of other threads are not changed.
That is, <em><b>contexts are managed on a per thread basis</b></em>.

For example, a servlet can build a per client request context
consisting of the client's host name and other information contained in
the the request. <em>Cookies</em> are another source of distinctive
information.

Contexts can be nested:
<ul>
 <li>when entering a context, initialize a <code>log4cxx::NDC</code>
 type variable with a distinctive string.
 If there is no nested diagnostic context for the
 current thread, a NDC stack will be created.
 The distinctive string will be automatically removed from the
 current thread's context stack when the variable goes out of scope.

 <li>when exiting a thread call NDC::remove to deal with any
 #push operation not matched with a corresponding #pop.
</ul>

If configured to do so, PatternLayout, xml::XMLLayout and
JSONLayout instances automatically retrieve the nested diagnostic
context for the current thread without any user intervention.
hence, even if a process is serving multiple clients simultaneously,
the logging events emanating from the same code
(belonging to the same logger)
can still be distinguished because each client
request will have a different tag.

#NDC implements <i>nested diagnostic contexts</i> as
defined by Neil Harrison in the article "Patterns for Logging
Diagnostic Messages" part of the book <i>"Pattern Languages of
Program Design 3"</i> edited by Martin et al.

*/
class LOG4CXX_EXPORT NDC
{
	public:
		/**
		 *  Pair of Message and FullMessage.
		 */
		typedef std::pair<LogString, LogString> DiagnosticContext;
		typedef std::stack<DiagnosticContext> Stack;

		/**
		 Add \c message onto the context stack.
		 @see The #push method.

		 @param message The text added to the diagnostic context information.
		 */
		NDC(const std::string& message);

		/**
		Remove the topmost element from the context stack associated with the current thread.

		@see The #pop method.
		*/
		~NDC();

		/**
		Clear any nested diagnostic information if any. This method is
		useful in cases where the same thread can be potentially used
		over and over in different unrelated contexts.
		*/
		static void clear();

		/**
		    Clone the diagnostic context for the current thread.
		    <p>Internally a diagnostic context is represented as a stack.  A
		    given thread can supply the stack (i.e. diagnostic context) to a
		    child thread so that the child can inherit the parent thread's
		    diagnostic context.
		    <p>The child thread uses the #inherit method to
		    inherit the parent's diagnostic context.
		    <p>If not passed to #inherit, returned stack should be deleted by caller.
		    @return Stack A clone of the current thread's diagnostic context, will not be null.
		*/
		static Stack* cloneStack();

		/**
		Inherit the diagnostic context of another thread.
		<p>The parent thread can obtain a reference to its diagnostic
		context using the #cloneStack method.  It should
		communicate this information to its child so that it may inherit
		the parent's diagnostic context.
		<p>The parent's diagnostic context is cloned before being
		inherited. In other words, once inherited, the two diagnostic
		contexts can be managed independently.
		@param stack The diagnostic context of the parent thread,
		    will be deleted during call.  If NULL, NDC will not be modified.
		*/
		static void inherit(Stack* stack);

		/**
		 *   Get the current value of the NDC of the
		 *   currrent thread.
		* @param dest destination to which to append content of NDC.
		* @return true if NDC is set.
		*/
		static bool get(LogString& dest);

		/**
		Get the current nesting depth of this diagnostic context.
		*/
		static int getDepth();


		/**
		* Tests if the NDC is empty.
		*/
		static bool empty();

		/**
		Get the value at the top of the stack
		associated with the current thread and then remove it.
		<p>The returned value is the value that was pushed last. If no
		context is available, then the empty string "" is returned.
		@return String The text of the innermost diagnostic context.
		*/
		static LogString pop();
		/**
		Append to \c buf the top value in the stack associated with the current thread and then remove it.
		@param buf to which top value is appended.
		@return true if NDC contained at least one value.
		*/
		static bool pop(std::string& buf);

		/**
		Get the value at the top of the stack
		associated with the current thread without removing it.
		<p>The returned value is the value that was pushed last. If no
		context is available, then the empty string "" is returned.
		@return String The text of the innermost diagnostic context.
		*/
		static LogString peek();
		/**
		Append to \c buf the top value in the stack associated with the current thread without removing it.
		@param buf to which top value is appended.
		@return true if NDC contained at least one value.
		*/
		static bool peek(std::string& buf);

		/**
		Add \c message to the stack associated with the current thread.
		<p>The contents of the <code>message</code> parameter is
		determined solely by the client.
		@param message The text added to the diagnostic context information.
		*/
		static void push(const std::string& message);
		/**
		Add \c message to the stack associated with the current thread.
		<p>The contents of the <code>message</code> parameter is
		determined solely by the client.
		@param message The text added to the diagnostic context information.
		*/
		static void pushLS(const LogString& message);

		/**
		Remove all the diagnostic context data for this thread.
		<p>A thread that adds to a diagnostic context by calling
		#push should call this method before exiting
		to prevent unbounded memory usage.
		*/
		static void remove();

#if LOG4CXX_WCHAR_T_API
		/**
		 Add \c message onto the context stack.
		 @see The #push method.

		 @param message The text added to the diagnostic context information.
		  */
		NDC(const std::wstring& message);
		/**
		Add \c message to the stack associated with the current thread.
		@param message The text added to the diagnostic context information.
		*/
		static void push(const std::wstring& message);
		/**
		Append to \c dst the top value in the stack associated with the current thread without removing it.
		@param dst to which top value is appended.
		@return true if NDC contained at least one value.
		 */
		static bool peek(std::wstring& dst);
		/**
		 *   Appends the current NDC content to the provided string and removes the value from the NDC.
		 *   @param dst destination.
		 *   @return true if NDC value set.
		 */
		static bool pop(std::wstring& dst);
#endif
#if LOG4CXX_UNICHAR_API
		/**
		 Add \c message onto the context stack.
		 @see The #push method.

		 @param message The text added to the diagnostic context information.
		*/
		NDC(const std::basic_string<UniChar>& message);
		/**
		Add \c message to the stack associated with the current thread.
		<p>The contents of the <code>message</code> parameter is
		determined solely by the client.
		@param message The text added to the diagnostic context information.
		*/
		static void push(const std::basic_string<UniChar>& message);
		/**
		Append to \c dst the top value in the stack associated with the current thread without removing it.
		@param dst to which top value is appended.
		@return true if NDC contained at least one value.
		 */
		static bool peek(std::basic_string<UniChar>& dst);
		/**
		Append to \c dst the top value in the stack associated with the current thread and then remove it.
		@param dst to which top value is appended.
		@return true if NDC contained at least one value.
		 */
		static bool pop(std::basic_string<UniChar>& dst);
#endif
#if LOG4CXX_CFSTRING_API
		/**
		 Add \c message onto the context stack.
		 @see The #push method.

		 @param message The text added to the diagnostic context information.
		  */
		NDC(const CFStringRef& message);
		/**
		Add \c message to the stack associated with the current thread.
		@param message The text added to the diagnostic context information.
		*/
		static void push(const CFStringRef& message);
		/**
		Append to \c dst the top value in the stack associated with the current thread without removing it.
		@param dst to which top value is appended.
		@return true if NDC contained at least one value.
		 */
		static bool peek(CFStringRef& dst);
		/**
		Append to \c dst the top value in the stack associated with the current thread and then remove it.
		@param dst to which top value is appended.
		@return true if NDC contained at least one value.
		 */
		static bool pop(CFStringRef& dst);
#endif

		static const LogString& getMessage(const DiagnosticContext& ctx);
		static const LogString& getFullMessage(const DiagnosticContext& ctx);
	private:
		NDC(const NDC&);
		NDC& operator=(const NDC&);
}; // class NDC;
}  // namespace log4cxx

#endif // _LOG4CXX_NDC_H
