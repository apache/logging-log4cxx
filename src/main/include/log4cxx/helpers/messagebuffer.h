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

#include <string>
#include <log4cxx/log4cxx.h>
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
        CharMessageBuffer& operator<<(const std::string& msg);
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
         *   This template allows any other insertion
         *   operator to operate on an encapsulated std::ostringstream
         *   created on demand.
         *   @param arg instance to append.
         *   @return reference to encapsulated std::ostringstream.
         */
        template<class T> 
        std::ostream& operator<<(T arg) {
           stream = new std::ostringstream();
           return *stream << buf << arg;
        }

        /**
         *  Gets the content of the encapsulated std::string.
         *  @param expression insertion expression whose type is used to
         *      determine whether to return the content of the encapsulated
         *      std::string or the encapsulated std::ostringstream.
         *  @return reference to encapsulated std::stream.
         */
        const std::string& str(const CharMessageBuffer& expression) const;
        /**
         *  Gets the content of the encapsulated std::ostringstream.
         *  @param expression insertion expression whose type is used to
         *      determine whether to return the content of the encapsulated
         *      std::string or the encapsulated std::ostringstream.
         *  @return content of encapsulated std::ostringstream.
         */
        std::string str(const std::ostream& expression) const;
        
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
        std::string buf;
        /**
         *  Encapsulated stream, created on demand.
         */
        std::ostringstream* stream;
   };

   

#if LOG4CXX_HAS_WCHAR_T           
   /**
    *   This class is used by the LOG4CXX_INFO and similar
    *   macros to support insertion operators in the message parameter.
    *   The class is not intended for use outside of that context.
    */
   class LOG4CXX_EXPORT WideMessageBuffer {
   public:
        /**
         *  Creates a new instance.
         *  @param msg initial content of buffer.
         */
        WideMessageBuffer(const wchar_t msg);
        /**
         *  Creates a new instance.
         *  @param msg initial content of buffer.
         */
        WideMessageBuffer(const wchar_t* msg);
        /**
         *  Creates a new instance.
         *  @param msg initial content of buffer.
         */
        WideMessageBuffer(const std::wstring& msg);
        /**
         *  Destructor.
         */
        ~WideMessageBuffer();

        /**
         *  Gets the content of the encapsulated std::wstring.
         *  @param expression insertion expression whose type is used to
         *      determine whether to return the content of the encapsulated
         *      std::wstring or the encapsulated std::wostringstream.
         *  @return reference to encapsulated std::wstream.
         */
        const std::wstring& str(const WideMessageBuffer&) const;
        /**
         *  Gets the content of the encapsulated std::wostringstream.
         *  @param expression insertion expression whose type is used to
         *      determine whether to return the content of the encapsulated
         *      std::wstring or the encapsulated std::wostringstream.
         *  @return content of encapsulated std::wostringstream.
         */
        std::wstring str(const std::wostream&) const;
         
        /**
         *   Appends character to buffer.
         *   @param msg character to append.
         *   @return this buffer.
         */
        WideMessageBuffer& operator<<(const std::wstring& msg);
        /**
         *   Appends character to buffer.
         *   @param msg character to append.
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
         *   This template allows any other insertion
         *   operator to operate on an encapsulated std::wostringstream
         *   created on demand.
         *   @param arg instance to append.
         *   @return reference to encapsulated std::wostringstream.
         */
        template<class T> 
        std::wostream& operator<<(T arg) {
           stream = new std::wostringstream();
           return *stream << buf << arg;
        }
         
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
         * Encapsulated std::wstring.
         */
        std::wstring buf;
        /**
         *  Encapsulated stream, created on demand.
         */
         std::wostringstream* stream;
   };
#endif   

   /**
    *   This class is used by the LOG4CXX_INFO and similar
    *   macros to support insertion operators in the message parameter.
    *   The class is not intended for use outside of that context.
    */
   class LOG4CXX_EXPORT MessageBuffer {
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
         *   Appends a string into the buffer and
         *   fixes the buffer to use char characters.
         *   @param msg message to append.
         *   @return encapsulated CharMessageBuffer.
         */
        CharMessageBuffer& operator<<(const std::string& msg);
        /**
         *   Appends a string into the buffer and
         *   fixes the buffer to use char characters.
         *   @param msg message to append.
         *   @return encapsulated CharMessageBuffer.
         */
        CharMessageBuffer& operator<<(const char* msg);
        /**
         *   Appends a string into the buffer and
         *   fixes the buffer to use char characters.
         *   @param msg message to append.
         *   @return encapsulated CharMessageBuffer.
         */
        CharMessageBuffer& operator<<(const char msg);
        
        /**
         *  Gets the content of the encapsulated std::string.
         *  @param expression insertion expression whose type is used to
         *      determine whether to return the content of the encapsulated
         *      std::string or the encapsulated std::ostringstream.
         *  @return reference to encapsulated std::stream.
         */
        const std::string& str(const CharMessageBuffer&) const;
        /**
         *  Gets the content of the encapsulated std::ostringstream.
         *  @param expression insertion expression whose type is used to
         *      determine whether to return the content of the encapsulated
         *      std::string or the encapsulated std::ostringstream.
         *  @return content of encapsulated std::ostringstream.
         */
        std::string str(const std::ostream&) const;

        /**
         *   This template allows any other insertion
         *   operator to operate on an encapsulated std::ostringstream
         *   created on demand and fixes the buffer to use char characters.
         *   @param arg instance to append.
         *   @return reference to encapsulated std::ostringstream.
         */
        template<class T> 
        std::ostream& operator<<(T arg) {
           return cbuf.operator<<(arg);
        }
        
        
#if LOG4CXX_HAS_WCHAR_T           
        /**
         *   Appends a wide string into the buffer and
         *   fixes the buffer to use wchar_t characters.
         *   @param msg message to append.
         *   @return encapsulated WideMessageBuffer.
         */
        WideMessageBuffer& operator<<(const std::wstring& msg);
        /**
         *   Appends a wide string into the buffer and
         *   fixes the buffer to use wchar_t characters.
         *   @param msg message to append.
         *   @return encapsulated WideMessageBuffer.
         */
        WideMessageBuffer& operator<<(const wchar_t* msg);
        /**
         *   Appends a wide character into the buffer and
         *   fixes the buffer to use wchar_t characters.
         *   @param msg message to append.
         *   @return encapsulated WideMessageBuffer.
         */
        WideMessageBuffer& operator<<(const wchar_t msg);

        /**
         *  Gets the content of the encapsulated std::wstring.
         *  @param expression insertion expression whose type is used to
         *      determine whether to return the content of the encapsulated
         *      std::wstring or the encapsulated std::wostringstream.
         *  @return reference to encapsulated std::wstream.
         */
        const std::wstring& str(const WideMessageBuffer&) const;
        /**
         *  Gets the content of the encapsulated std::wostringstream.
         *  @param expression insertion expression whose type is used to
         *      determine whether to return the content of the encapsulated
         *      std::wstring or the encapsulated std::wostringstream.
         *  @return content of encapsulated std::wostringstream.
         */
        std::wstring str(const std::wostream&) const;
private:
        /**
         * Encapsulated wide message buffer, created on demand.
         */
        WideMessageBuffer* wbuf;        
#endif
   };

}
}

#endif

