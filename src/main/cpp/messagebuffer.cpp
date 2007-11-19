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
#include <log4cxx/helpers/transcoder.h>

using namespace log4cxx::helpers;

CharMessageBuffer::CharMessageBuffer() : stream(0) {}

CharMessageBuffer::~CharMessageBuffer() {
	delete stream;
}

CharMessageBuffer& CharMessageBuffer::operator<<(const std::basic_string<char>& msg) {
	if (stream == 0) {
		buf.append(msg);
	} else {
		*stream << msg;
	}
	return *this;
}

CharMessageBuffer& CharMessageBuffer::operator<<(const char* msg) {
	const char* actualMsg = msg;
	if (actualMsg == 0) {
		actualMsg = "null";
	}
	if (stream == 0) {
		buf.append(actualMsg);
	} else {
		*stream << actualMsg;
	}
	return *this;
}
CharMessageBuffer& CharMessageBuffer::operator<<(char* msg) {
	return operator<<((const char*) msg);
}

CharMessageBuffer& CharMessageBuffer::operator<<(const char msg) {
	if (stream == 0) {
		buf.append(1, msg);
	} else {
		buf.assign(1, msg);
		*stream << buf;
	}
	return *this;
}

CharMessageBuffer::operator std::basic_ostream<char>&() {
	if (stream == 0) {
	  stream = new std::basic_ostringstream<char>();
	  if (!buf.empty()) {
		  *stream << buf;
	  }
	}
	return *stream;
}

const std::basic_string<char>& CharMessageBuffer::str(std::basic_ostream<char>&) {
	buf = stream->str();
	return buf;
}

const std::basic_string<char>& CharMessageBuffer::str(CharMessageBuffer&) {
	return buf;
}

bool CharMessageBuffer::hasStream() const {
    return (stream != 0);
}

std::ostream& CharMessageBuffer::operator<<(ios_base_manip manip) {
	std::ostream& s = *this;
	(*manip)(s);
	return s;
}

std::ostream& CharMessageBuffer::operator<<(bool val) { return ((std::ostream&) *this).operator<<(val); }
std::ostream& CharMessageBuffer::operator<<(short val) { return ((std::ostream&) *this).operator<<(val); }
std::ostream& CharMessageBuffer::operator<<(int val) { return ((std::ostream&) *this).operator<<(val); }
std::ostream& CharMessageBuffer::operator<<(unsigned int val) { return ((std::ostream&) *this).operator<<(val); }
std::ostream& CharMessageBuffer::operator<<(long val) { return ((std::ostream&) *this).operator<<(val); }
std::ostream& CharMessageBuffer::operator<<(unsigned long val) { return ((std::ostream&) *this).operator<<(val); }
std::ostream& CharMessageBuffer::operator<<(float val) { return ((std::ostream&) *this).operator<<(val); }
std::ostream& CharMessageBuffer::operator<<(double val) { return ((std::ostream&) *this).operator<<(val); }
std::ostream& CharMessageBuffer::operator<<(long double val) { return ((std::ostream&) *this).operator<<(val); }
std::ostream& CharMessageBuffer::operator<<(void* val) { return ((std::ostream&) *this).operator<<(val); }


#if LOG4CXX_HAS_WCHAR_T
WideMessageBuffer::WideMessageBuffer() : stream(0) {}

WideMessageBuffer::~WideMessageBuffer() {
	delete stream;
}

WideMessageBuffer& WideMessageBuffer::operator<<(const std::basic_string<wchar_t>& msg) {
	if (stream == 0) {
		buf.append(msg);
	} else {
		*stream << msg;
	}
	return *this;
}

WideMessageBuffer& WideMessageBuffer::operator<<(const wchar_t* msg) {
	const wchar_t* actualMsg = msg;
	if (actualMsg == 0) {
		actualMsg = L"null";
	}
	if (stream == 0) {
		buf.append(actualMsg);
	} else {
		*stream << actualMsg;
	}
	return *this;
}

WideMessageBuffer& WideMessageBuffer::operator<<(wchar_t* msg) {
	return operator<<((const wchar_t*) msg);
}

WideMessageBuffer& WideMessageBuffer::operator<<(const wchar_t msg) {
	if (stream == 0) {
		buf.append(1, msg);
	} else {
		buf.assign(1, msg);
		*stream << buf;
	}
	return *this;
}

WideMessageBuffer::operator std::basic_ostream<wchar_t>&() {
	if (stream == 0) {
	  stream = new std::basic_ostringstream<wchar_t>();
	  if (!buf.empty()) {
		  *stream << buf;
	  }
	}
	return *stream;
}

const std::basic_string<wchar_t>& WideMessageBuffer::str(std::basic_ostream<wchar_t>&) {
	buf = stream->str();
	return buf;
}

const std::basic_string<wchar_t>& WideMessageBuffer::str(WideMessageBuffer&) {
	return buf;
}

bool WideMessageBuffer::hasStream() const {
    return (stream != 0);
}

std::wostream& WideMessageBuffer::operator<<(ios_base_manip manip) {
	std::wostream& s = *this;
	(*manip)(s);
	return s;
}

std::wostream& WideMessageBuffer::operator<<(bool val) { return ((std::wostream&) *this).operator<<(val); }
std::wostream& WideMessageBuffer::operator<<(short val) { return ((std::wostream&) *this).operator<<(val); }
std::wostream& WideMessageBuffer::operator<<(int val) { return ((std::wostream&) *this).operator<<(val); }
std::wostream& WideMessageBuffer::operator<<(unsigned int val) { return ((std::wostream&) *this).operator<<(val); }
std::wostream& WideMessageBuffer::operator<<(long val) { return ((std::wostream&) *this).operator<<(val); }
std::wostream& WideMessageBuffer::operator<<(unsigned long val) { return ((std::wostream&) *this).operator<<(val); }
std::wostream& WideMessageBuffer::operator<<(float val) { return ((std::wostream&) *this).operator<<(val); }
std::wostream& WideMessageBuffer::operator<<(double val) { return ((std::wostream&) *this).operator<<(val); }
std::wostream& WideMessageBuffer::operator<<(long double val) { return ((std::wostream&) *this).operator<<(val); }
std::wostream& WideMessageBuffer::operator<<(void* val) { return ((std::wostream&) *this).operator<<(val); }


MessageBuffer::MessageBuffer()  : wbuf(0){
}

MessageBuffer::~MessageBuffer() {
    delete wbuf;
}

bool MessageBuffer::hasStream() const {
    return cbuf.hasStream() || (wbuf != 0 && wbuf->hasStream());
}

std::ostream& MessageBuffer::operator<<(ios_base_manip manip) {
	std::ostream& s = *this;
	(*manip)(s);
	return s;
}

MessageBuffer::operator std::ostream&() {
	return (std::ostream&) cbuf;
}

CharMessageBuffer& MessageBuffer::operator<<(const std::string& msg) {
	return cbuf.operator<<(msg);
}

CharMessageBuffer& MessageBuffer::operator<<(const char* msg) {
	return cbuf.operator<<(msg);
}
CharMessageBuffer& MessageBuffer::operator<<(char* msg) {
	return cbuf.operator<<((const char*) msg);
}

CharMessageBuffer& MessageBuffer::operator<<(const char msg) {
	return cbuf.operator<<(msg);
}

const std::string& MessageBuffer::str(CharMessageBuffer& buf) {
	return cbuf.str(buf);
}

const std::string& MessageBuffer::str(std::ostream& os) {
	return cbuf.str(os);
}

WideMessageBuffer& MessageBuffer::operator<<(const std::wstring& msg) {
	wbuf = new WideMessageBuffer();
	return (*wbuf) << msg;
}

WideMessageBuffer& MessageBuffer::operator<<(const wchar_t* msg) {
	wbuf = new WideMessageBuffer();
	return (*wbuf) << msg;
}
WideMessageBuffer& MessageBuffer::operator<<(wchar_t* msg) {
	wbuf = new WideMessageBuffer();
	return (*wbuf) << (const wchar_t*) msg;
}

WideMessageBuffer& MessageBuffer::operator<<(const wchar_t msg) {
	wbuf = new WideMessageBuffer();
	return (*wbuf) << msg;
}

const std::wstring& MessageBuffer::str(WideMessageBuffer& buf) {
	return wbuf->str(buf);
}

const std::wstring& MessageBuffer::str(std::wostream& os) {
	return wbuf->str(os);
}

std::ostream& MessageBuffer::operator<<(bool val) { return cbuf.operator<<(val); }
std::ostream& MessageBuffer::operator<<(short val) { return cbuf.operator<<(val); }
std::ostream& MessageBuffer::operator<<(int val) { return cbuf.operator<<(val); }
std::ostream& MessageBuffer::operator<<(unsigned int val) { return cbuf.operator<<(val); }
std::ostream& MessageBuffer::operator<<(long val) { return cbuf.operator<<(val); }
std::ostream& MessageBuffer::operator<<(unsigned long val) { return cbuf.operator<<(val); }
std::ostream& MessageBuffer::operator<<(float val) { return cbuf.operator<<(val); }
std::ostream& MessageBuffer::operator<<(double val) { return cbuf.operator<<(val); }
std::ostream& MessageBuffer::operator<<(long double val) { return cbuf.operator<<(val); }
std::ostream& MessageBuffer::operator<<(void* val) { return cbuf.operator<<(val); }


#endif
