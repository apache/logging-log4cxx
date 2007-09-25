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
#include <ostream>
#include <sstream>

namespace log4cxx {
   namespace helpers {
   
   class LOG4CXX_EXPORT CharMessageBuffer {
   public:
        CharMessageBuffer();
        ~CharMessageBuffer();
        
        CharMessageBuffer& operator<<(const std::string& msg);
        CharMessageBuffer& operator<<(const char* msg);
        CharMessageBuffer& operator<<(const char msg);
        
        template<class T> 
        std::ostream& operator<<(T arg) {
           stream = new std::ostringstream();
           return *stream << buf << arg;
        }

        const std::string& str(const CharMessageBuffer&) const;
        std::string str(const std::ostream&) const;
        
   private:
        std::string buf;
        std::ostringstream* stream;
   };

   

#if LOG4CXX_HAS_WCHAR_T           
   class LOG4CXX_EXPORT WideMessageBuffer {
   public:
        WideMessageBuffer(const wchar_t);
        WideMessageBuffer(const wchar_t*);
        WideMessageBuffer(const std::wstring&);
        ~WideMessageBuffer();

        const std::wstring& str(const WideMessageBuffer&) const;
        std::wstring str(const std::wostream&) const;
         
        WideMessageBuffer& operator<<(const std::wstring& msg);
        WideMessageBuffer& operator<<(const wchar_t* msg);
        WideMessageBuffer& operator<<(const wchar_t msg);

        template<class T> 
        std::wostream& operator<<(T arg) {
           stream = new std::wostringstream();
           return *stream << buf << arg;
        }
         
   private:
         std::wstring buf;
         std::wostringstream* stream;
   };

   class LOG4CXX_EXPORT MessageBuffer : public CharMessageBuffer {
   public:
        MessageBuffer();
        ~MessageBuffer();
        
        WideMessageBuffer& operator<<(const std::wstring& msg);
        WideMessageBuffer& operator<<(const wchar_t* msg);
        WideMessageBuffer& operator<<(const wchar_t msg);

        CharMessageBuffer& operator<<(const std::string& msg);
        CharMessageBuffer& operator<<(const char* msg);
        CharMessageBuffer& operator<<(const char msg);

        const std::wstring& str(const WideMessageBuffer&) const;
        std::wstring str(const std::wostream&) const;
        const std::string& str(const CharMessageBuffer&) const;
        std::string str(const std::ostream&) const;

        template<class T> 
        std::ostream& operator<<(T arg) {
           return CharMessageBuffer::operator<<(arg);
        }




   private:
        WideMessageBuffer* wbuf;        
   };
#else
typedef class CharMessageBuffer MessageBuffer;
#endif

}
}

#endif

