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



MessageBuffer::MessageBuffer()  : wbuf(0){
}

MessageBuffer::~MessageBuffer() {
    delete wbuf;
}

bool MessageBuffer::hasStream() const {
    return cbuf.hasStream() || (wbuf != 0 && wbuf->hasStream());
}

#endif
