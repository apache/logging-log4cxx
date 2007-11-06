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

#ifndef _LOG4CXX_MESSAGE_BUFFER_H
#define _LOG4CXX_MESSAGE_BUFFER_H

#include <log4cxx/log4cxx.h>
#include <string>
#include <sstream>

namespace log4cxx {


   namespace helpers {
   

   /**
    *   This class is used by the LOG4CXX_INFO and similar
    *   macros to support insertion operators in the message parameter.
    *   The class is not intended for use outside of that context.
    */
   class LOG4CXX_EXPORT CharMessageBuffer {
   public:
        /**
         *  Creates a new instance.
         */
	    CharMessageBuffer();
        /**
         *  Destructor.
         */
        ~CharMessageBuffer();

        
        /**
         *   Appends string to buffer.
         *   @param msg string append.
         *   @return this buffer.
         */
        CharMessageBuffer& operator<<(const std::basic_string<char>& msg);
        /**
         *   Appends string to buffer.
         *   @param msg string to append.
         *   @return this buffer.
         */
        CharMessageBuffer& operator<<(const char* msg);

        /**
         *   Appends character to buffer.
         *   @param msg character to append.
         *   @return this buffer.
         */
        CharMessageBuffer& operator<<(const char msg);

		/**
		 *  Cast to ostream.
		 */
		operator std::basic_ostream<char>&();

		/**
		 *   Get content of buffer.
		 *   @param os used only to signal that
		 *       the embedded stream was used.
		 */
		const std::basic_string<char>& str(std::basic_ostream<char>& os);

		/**
		 *   Get content of buffer.
		 *   @param buf used only to signal that
		 *       the embedded stream was not used.
		 */
		const std::basic_string<char>& str(CharMessageBuffer& buf);

   private:
        /**
         * Prevent use of default copy constructor.
         */
	   CharMessageBuffer(const CharMessageBuffer&);
        /**
         *   Prevent use of default assignment operator.  
         */
	   CharMessageBuffer& operator=(const CharMessageBuffer&);

	   /**
         * Encapsulated std::string.
         */
        std::basic_string<char> buf;
        /**
         *  Encapsulated stream, created on demand.
         */
        std::basic_ostringstream<char>* stream;
   };

template<class V>
std::basic_ostream<char>& operator<<(CharMessageBuffer& os, const V& val) {
	return ((std::basic_ostream<char>&) os) << val;
}

inline std::basic_ostream<char>& operator<<(CharMessageBuffer& os, std::ios_base& (*manip)(std::ios_base& s)) {
	std::basic_ostream<char>& s = os;
	(*manip)(s);
	return s;
}


#if LOG4CXX_HAS_WCHAR_T
   /**
    *   This class is designed to support insertion operations
	*   in the message argument to the LOG4CXX_INFO and similar
	*   macros and is not designed for general purpose use.
	*/
   class LOG4CXX_EXPORT WideMessageBuffer {
   public:
        /**
         *  Creates a new instance.
         */
	    WideMessageBuffer();
        /**
         *  Destructor.
         */
        ~WideMessageBuffer();

        
        /**
         *   Appends string to buffer.
         *   @param msg string append.
         *   @return this buffer.
         */
        WideMessageBuffer& operator<<(const std::basic_string<wchar_t>& msg);
        /**
         *   Appends string to buffer.
         *   @param msg string to append.
         *   @return this buffer.
         */
        WideMessageBuffer& operator<<(const wchar_t* msg);

        /**
         *   Appends character to buffer.
         *   @param msg character to append.
         *   @return this buffer.
         */
        WideMessageBuffer& operator<<(const wchar_t msg);

		/**
		 *  Cast to ostream.
		 */
		operator std::basic_ostream<wchar_t>&();

		/**
		 *   Get content of buffer.
		 *   @param os used only to signal that
		 *       the embedded stream was used.
		 */
		const std::basic_string<wchar_t>& str(std::basic_ostream<wchar_t>& os);

		/**
		 *   Get content of buffer.
		 *   @param buf used only to signal that
		 *       the embedded stream was not used.
		 */
		const std::basic_string<wchar_t>& str(WideMessageBuffer& buf);

   private:
        /**
         * Prevent use of default copy constructor.
         */
	   WideMessageBuffer(const WideMessageBuffer&);
        /**
         *   Prevent use of default assignment operator.  
         */
	   WideMessageBuffer& operator=(const WideMessageBuffer&);

	   /**
         * Encapsulated std::string.
         */
        std::basic_string<wchar_t> buf;
        /**
         *  Encapsulated stream, created on demand.
         */
        std::basic_ostringstream<wchar_t>* stream;
   };

template<class V>
std::basic_ostream<wchar_t>& operator<<(WideMessageBuffer& os, const V& val) {
	return ((std::basic_ostream<wchar_t>&) os) << val;
}

inline std::basic_ostream<wchar_t>& operator<<(WideMessageBuffer& os, std::ios_base& (*manip)(std::ios_base& s)) {
	std::basic_ostream<wchar_t>& s = os;
	(*manip)(s);
	return s;
}



   /**
    *   This class is used by the LOG4CXX_INFO and similar
    *   macros to support insertion operators in the message parameter.
    *   The class is not intended for use outside of that context.
    */
   class LOG4CXX_EXPORT MessageBuffer {
   public:
        /**
         *  Creates a new instance.
         */
	   MessageBuffer();
	   /**
         * Destructor.
         */
	   ~MessageBuffer();

		/**
		 *  Cast to ostream.
		 */
		inline operator std::ostream&() {
			return (std::ostream&) cbuf;
        }

	   /**
         *   Appends a string into the buffer and
         *   fixes the buffer to use char characters.
         *   @param msg message to append.
         *   @return encapsulated CharMessageBuffer.
         */
        inline CharMessageBuffer& operator<<(const std::string& msg) {
			return cbuf.operator<<(msg);
		}
        /**
         *   Appends a string into the buffer and
         *   fixes the buffer to use char characters.
         *   @param msg message to append.
         *   @return encapsulated CharMessageBuffer.
         */
        inline CharMessageBuffer& operator<<(const char* msg) {
			return cbuf.operator<<(msg);
		}

        /**
         *   Appends a string into the buffer and
         *   fixes the buffer to use char characters.
         *   @param msg message to append.
         *   @return encapsulated CharMessageBuffer.
         */
        inline CharMessageBuffer& operator<<(const char msg) {
			return cbuf.operator<<(msg);
		}

		/**
		 *   Get content of buffer.
		 *   @param buf used only to signal
		 *       the character type and that
		 *       the embedded stream was not used.
		 */
		inline const std::string& str(CharMessageBuffer& buf) {
			return cbuf.str(buf);
		}

		/**
		 *   Get content of buffer.
		 *   @param os used only to signal 
		 *       the character type and that
		 *       the embedded stream was used.
		 */
		inline const std::string& str(std::ostream& os) {
			return cbuf.str(os);
		}

	   /**
         *   Appends a string into the buffer and
         *   fixes the buffer to use char characters.
         *   @param msg message to append.
         *   @return encapsulated CharMessageBuffer.
         */
        inline WideMessageBuffer& operator<<(const std::wstring& msg) {
			wbuf = new WideMessageBuffer();
			return (*wbuf) << msg;
		}
        /**
         *   Appends a string into the buffer and
         *   fixes the buffer to use char characters.
         *   @param msg message to append.
         *   @return encapsulated CharMessageBuffer.
         */
        inline WideMessageBuffer& operator<<(const wchar_t* msg) {
			wbuf = new WideMessageBuffer();
			return (*wbuf) << msg;
		}
        /**
         *   Appends a string into the buffer and
         *   fixes the buffer to use char characters.
         *   @param msg message to append.
         *   @return encapsulated CharMessageBuffer.
         */
        inline WideMessageBuffer& operator<<(const wchar_t msg) {
			wbuf = new WideMessageBuffer();
			return (*wbuf) << msg;
		}

		/**
		 *   Get content of buffer.
		 *   @param buf used only to signal
		 *       the character type and that
		 *       the embedded stream was not used.
		 */
		inline const std::wstring& str(WideMessageBuffer& buf) {
			return wbuf->str(buf);
		}

		/**
		 *   Get content of buffer.
		 *   @param os used only to signal 
		 *       the character type and that
		 *       the embedded stream was used.
		 */
		inline const std::wstring& str(std::wostream& os) {
			return wbuf->str(os);
		}


   private:
        /**
         * Prevent use of default copy constructor.
         */
        MessageBuffer(const MessageBuffer&);
        /**
         *   Prevent use of default assignment operator.  
         */
        MessageBuffer& operator=(const MessageBuffer&);

        /**
         *  Character message buffer.
         */
        CharMessageBuffer cbuf;

        /**
         * Encapsulated wide message buffer, created on demand.
         */
        WideMessageBuffer* wbuf;        
   };

template<class V>
std::ostream& operator<<(MessageBuffer& os, const V& val) {
	return ((std::ostream&) os) << val;
}

inline std::ostream& operator<<(MessageBuffer& os, std::ios_base& (*manip)(std::ios_base& s)) {
	std::ostream& s = os;
	(*manip)(s);
	return s;
}

#if LOG4CXX_LOGCHAR_IS_UTF8
typedef CharMessageBuffer LogCharMessageBuffer;
#endif

#if LOG4CXX_LOGCHAR_IS_WCHAR
typedef WideMessageBuffer LogCharMessageBuffer;
#endif

#else
typedef CharMessageBuffer MessageBuffer;
typedef CharMessageBuffer LogCharMessageBuffer;
#endif

}}
#endif

