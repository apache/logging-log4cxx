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

#if defined(_MSC_VER)
#pragma warning ( disable: 4786 4231 )
#endif


#include <log4cxx/ndc.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/threadspecificdata.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

NDC::DiagnosticContext::DiagnosticContext(const LogString& message1,
        const DiagnosticContext * parent)
        : fullMessage(message1), message(message1)
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
        : fullMessage(src.fullMessage), message(src.message) {
}

NDC::DiagnosticContext& NDC::DiagnosticContext::operator=(
        const DiagnosticContext& src)
{
        message.assign(src.message);
        fullMessage.assign(src.fullMessage);
        return *this;
}


NDC::NDC(const std::string& message)
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

bool NDC::get(LogString& dest)
{
        Stack& stack = ThreadSpecificData::getCurrentThreadStack();
        if(!stack.empty())
        {
                dest.append(stack.top().fullMessage);
                return true;
        }
        return false;
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

bool NDC::pop(std::string& dst)
{
        Stack& stack = ThreadSpecificData::getCurrentThreadStack();
        if(!stack.empty())
        {
                Transcoder::encode(stack.top().message, dst);
                stack.pop();
                return true;
        }
        return false;
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

bool NDC::peek(std::string& dst)
{
        Stack& stack = ThreadSpecificData::getCurrentThreadStack();
        if(!stack.empty())
        {
                Transcoder::encode(stack.top().message, dst);
                return true;
        }
        return false;
}

void NDC::pushLS(const LogString& message)
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
   pushLS(msg);
}

void NDC::remove()
{
        clear();
}

bool NDC::empty() {
    Stack& stack = ThreadSpecificData::getCurrentThreadStack();
    return stack.empty();
}

#if LOG4CXX_WCHAR_T_API
NDC::NDC(const std::wstring& message)
{
        push(message);
}

void NDC::push(const std::wstring& message)
{
   LOG4CXX_DECODE_WCHAR(msg, message);
   pushLS(msg);
}

bool NDC::pop(std::wstring& dst)
{
        Stack& stack = ThreadSpecificData::getCurrentThreadStack();
        if(!stack.empty())
        {
                Transcoder::encode(stack.top().message, dst);
                stack.pop();
                return true;
        }
        return false;
}

bool NDC::peek(std::wstring& dst)
{
        Stack& stack = ThreadSpecificData::getCurrentThreadStack();
        if(!stack.empty())
        {
                Transcoder::encode(stack.top().message, dst);
                return true;
        }
        return false;
}

#endif


#if LOG4CXX_UNICHAR_API
NDC::NDC(const std::basic_string<UniChar>& message)
{
        push(message);
}

void NDC::push(const std::basic_string<UniChar>& message)
{
   LOG4CXX_DECODE_UNICHAR(msg, message);
   pushLS(msg);
}

bool NDC::pop(std::basic_string<UniChar>& dst)
{
        Stack& stack = ThreadSpecificData::getCurrentThreadStack();
        if(!stack.empty())
        {
                Transcoder::encode(stack.top().message, dst);
                stack.pop();
                return true;
        }
        return false;
}

bool NDC::peek(std::basic_string<UniChar>& dst)
{
        Stack& stack = ThreadSpecificData::getCurrentThreadStack();
        if(!stack.empty())
        {
                Transcoder::encode(stack.top().message, dst);
                return true;
        }
        return false;
}

#endif


#if LOG4CXX_CFSTRING_API
NDC::NDC(const CFStringRef& message)
{
        push(message);
}

void NDC::push(const CFStringRef& message)
{
   LOG4CXX_DECODE_CFSTRING(msg, message);
   pushLS(msg);
}

bool NDC::pop(CFStringRef& dst)
{
        Stack& stack = ThreadSpecificData::getCurrentThreadStack();
        if(!stack.empty())
        {
                dst = Transcoder::encode(stack.top().message);
                stack.pop();
                return true;
        }
        return false;
}

bool NDC::peek(CFStringRef& dst)
{
        Stack& stack = ThreadSpecificData::getCurrentThreadStack();
        if(!stack.empty())
        {
                dst = Transcoder::encode(stack.top().message);
                return true;
        }
        return false;
}

#endif

