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

#include <log4cxx/helpers/messagebuffer.h>

using namespace log4cxx::helpers;

CharMessageBuffer::CharMessageBuffer() {
    stream = 0;
}

CharMessageBuffer::~CharMessageBuffer() {
    delete stream;
}

CharMessageBuffer& CharMessageBuffer::operator<<(const std::string& msg) {
    buf.append(msg);
    return *this;
}

CharMessageBuffer& CharMessageBuffer::operator<<(const char* msg) {
    if (0 == msg) {
       buf.append("null");
    } else {
       buf.append(msg);
    }
    return *this;
}

CharMessageBuffer& CharMessageBuffer::operator<<(const char msg) {
    buf.append(1, msg);
    return *this;
}
        
const std::string& CharMessageBuffer::str(const CharMessageBuffer&) const {
    return buf;
}

std::string CharMessageBuffer::str(const std::ostream&) const {
    return stream->str();
}

MessageBuffer::MessageBuffer()  
#if LOG4CXX_HAS_WCHAR_T
    : wbuf(0)
#endif 
{
}

MessageBuffer::~MessageBuffer() {
#if LOG4CXX_HAS_WCHAR_T
    delete wbuf;
#endif
}


CharMessageBuffer& MessageBuffer::operator<<(const std::string& msg) {
    return cbuf.operator<<(msg);
}

CharMessageBuffer& MessageBuffer::operator<<(const char* msg) {
    return cbuf.operator<<(msg);
}

CharMessageBuffer& MessageBuffer::operator<<(const char msg) {
    return cbuf.operator<<(msg);
}

const std::string& MessageBuffer::str(const CharMessageBuffer& msg) const {
    return cbuf.str(msg);
}

std::string MessageBuffer::str(const std::ostream& msg) const {
    return cbuf.str(msg);
}


#if LOG4CXX_HAS_WCHAR_T
WideMessageBuffer& MessageBuffer::operator<<(const std::wstring& msg) {
   wbuf = new WideMessageBuffer(msg);
   return *wbuf;
}
   
WideMessageBuffer& MessageBuffer::operator<<(const wchar_t* msg) {
   if (0 == msg) {
       wbuf = new WideMessageBuffer(L"null");
   } else {
       wbuf = new WideMessageBuffer(msg);
   }
   return *wbuf;
}

WideMessageBuffer& MessageBuffer::operator<<(const wchar_t msg) {
   wbuf = new WideMessageBuffer(msg);
   return *wbuf;
}

const std::wstring& MessageBuffer::str(const WideMessageBuffer& wide) const {
    return wbuf->str(wide);
}

std::wstring MessageBuffer::str(const std::wostream& wstr) const {
    return wbuf->str(wstr);
}

WideMessageBuffer::WideMessageBuffer(const wchar_t msg) : buf(1, msg), stream(0) {
}

WideMessageBuffer::WideMessageBuffer(const wchar_t* msg) : buf(msg), stream(0) {
}

WideMessageBuffer::WideMessageBuffer(const std::wstring& msg) : buf(msg), stream(0) {
}

WideMessageBuffer::~WideMessageBuffer()  {
    delete stream;
}

const std::wstring& WideMessageBuffer::str(const WideMessageBuffer&) const {
    return buf;
}

std::wstring WideMessageBuffer::str(const std::wostream&) const {
    return stream->str();
}

WideMessageBuffer& WideMessageBuffer::operator<<(const std::wstring& msg) {
    buf.append(msg);
    return *this;
}

WideMessageBuffer& WideMessageBuffer::operator<<(const wchar_t* msg) {
    if (0 == msg) {
        buf.append(L"null");
    } else {
        buf.append(msg);
    }
    return *this;
}

WideMessageBuffer& WideMessageBuffer::operator<<(const wchar_t msg) {
    buf.append(1, msg);
    return *this;
}



#endif



