/*
 * Copyright 2003,2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <log4cxx/ndc.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/threadspecificdata.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

NDC::DiagnosticContext::DiagnosticContext(const LogString& message,
        const DiagnosticContext * parent)
        : message(message), fullMessage(message)
{
        if (parent != 0)
        {
                fullMessage.insert(0, LOG4CXX_STR(" "));
                fullMessage.insert(0, parent->fullMessage);
        }
}

NDC::DiagnosticContext::~DiagnosticContext() {
}

NDC::DiagnosticContext::DiagnosticContext(const DiagnosticContext& src)
        : message(src.message), fullMessage(src.fullMessage) {
}

NDC::DiagnosticContext& NDC::DiagnosticContext::operator=(
        const DiagnosticContext& src)
{
        message.assign(src.message);
        fullMessage.assign(src.fullMessage);
        return *this;
}

NDC::NDC(const LogString& message)
{
        push(message);
}

NDC::~NDC()
{
        pop();
}


void NDC::clear()
{
        Stack& stack = ThreadSpecificData::getCurrentThreadStack();
        while(!stack.empty()) {
          stack.pop();
        }
}

#if 0
NDC::Stack * NDC::cloneStack()
{
        Stack * stack = getCurrentThreadStack();
        if(stack != 0)
        {
                return new Stack(*stack);
        }
        else
        {
                return new Stack();
        }
}

void NDC::inherit(NDC::Stack * stack)
{
        if(stack != 0)
        {
                setCurrentThreadStack(stack);
        }
}

#endif
LogString NDC::get()
{
        Stack& stack = ThreadSpecificData::getCurrentThreadStack();
        if(!stack.empty())
        {
                return stack.top().fullMessage;
        }
        return LogString();
}

int NDC::getDepth()
{
  return ThreadSpecificData::getCurrentThreadStack().size();
}

LogString NDC::pop()
{
        Stack& stack = ThreadSpecificData::getCurrentThreadStack();
        if(!stack.empty())
        {
                LogString value(stack.top().message);
                stack.pop();
                return value;
        }
        return LogString();
}

LogString NDC::peek()
{
        Stack& stack = ThreadSpecificData::getCurrentThreadStack();
        if(!stack.empty())
        {
                return stack.top().message;
        }
        return LogString();
}

void NDC::pushLogString(const LogString& message)
{
        Stack& stack = ThreadSpecificData::getCurrentThreadStack();

        if (stack.empty())
        {
                stack.push(DiagnosticContext(message, 0));
        }
        else
        {
                DiagnosticContext& parent = stack.top();
                stack.push(DiagnosticContext(message, &parent));
        }
}

void NDC::push(const std::string& message)
{
   LOG4CXX_DECODE_CHAR(msg, message);
   pushLogString(msg);
}

void NDC::push(const std::wstring& message)
{
   LOG4CXX_DECODE_WCHAR(msg, message);
   pushLogString(msg);
}

void NDC::remove()
{
        clear();
}

