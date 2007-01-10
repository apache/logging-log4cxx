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

#include <log4cxx/logstring.h>
#include <log4cxx/helpers/exception.h>
#include <string.h>
#include <string>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/pool.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

Exception::Exception(const std::string& msg1) {
  size_t msgLen = msg1.length();
  if (msgLen > MSG_SIZE) msgLen = MSG_SIZE;
  memcpy(this->msg, (char*) msg1.data(), msgLen);
  this->msg[msgLen] = 0;
}

Exception::Exception(const Exception& src) : std::exception() {
#if defined(__STDC_LIB_EXT1__) || defined(__STDC_SECURE_LIB__)
      strcpy_s(msg, sizeof msg, src.msg);
#else
      strcpy(msg, src.msg);
#endif
}

Exception& Exception::operator=(const Exception& src) {
#if defined(__STDC_LIB_EXT1__) || defined(__STDC_SECURE_LIB__)
      strcpy_s(msg, sizeof msg, src.msg);
#else
      strcpy(msg, src.msg);
#endif
  return *this;
}

const char* Exception::what() const throw() {
  return msg;
}


RuntimeException::RuntimeException(const std::string& msg1)
     : Exception(msg1) {
}

RuntimeException::RuntimeException(const RuntimeException& src)
      : Exception(src) {
}

RuntimeException& RuntimeException::operator=(const RuntimeException& src) {
      Exception::operator=(src);
      return *this;
}

NullPointerException::NullPointerException(const std::string& msg1)
     : RuntimeException(msg1) {
}

NullPointerException::NullPointerException(const NullPointerException& src)
      : RuntimeException(src) {
}

NullPointerException& NullPointerException::operator=(const NullPointerException& src) {
      RuntimeException::operator=(src);
      return *this;
}

IllegalArgumentException::IllegalArgumentException(const std::string& msg1)
     : RuntimeException(msg1) {
}

IllegalArgumentException::IllegalArgumentException(const IllegalArgumentException& src)
      : RuntimeException(src) {
}

IllegalArgumentException& IllegalArgumentException::operator=(const IllegalArgumentException& src) {
      RuntimeException::operator=(src);
      return *this;
}

IOException::IOException()
     : Exception("IO exception") {
}

IOException::IOException(log4cxx_status_t stat)
    : Exception(formatMessage(stat)) {
}


IOException::IOException(const std::string& msg1)
     : Exception(msg1) {
}

IOException::IOException(const IOException& src)
      : Exception(src) {
}

IOException& IOException::operator=(const IOException& src) {
      Exception::operator=(src);
      return *this;
}

std::string IOException::formatMessage(log4cxx_status_t stat) {
   std::string s("IO Exception : status code = ");
   Pool p;
   StringHelper::toString(stat, p, s);
   return s;
}


MissingResourceException::MissingResourceException(const LogString& key)
    : Exception(formatMessage(key)) {
}


MissingResourceException::MissingResourceException(const MissingResourceException& src)
      : Exception(src) {
}

MissingResourceException& MissingResourceException::operator=(const MissingResourceException& src) {
      Exception::operator=(src);
      return *this;
}

std::string MissingResourceException::formatMessage(const LogString& key) {
   std::string s("MissingResourceException: resource key = \"");
   Transcoder::encode(key, s);
   s.append("\".");
   return s;
}

PoolException::PoolException(log4cxx_status_t stat)
    : Exception(formatMessage(stat)) {
}

PoolException::PoolException(const PoolException &src)
   : Exception(src) {
}

PoolException& PoolException::operator=(const PoolException& src) {
     Exception::operator=(src);
     return *this;
}

std::string PoolException::formatMessage(log4cxx_status_t) {
     return "Pool exception";
}


TranscoderException::TranscoderException(log4cxx_status_t stat)
    : Exception(formatMessage(stat)) {
}

TranscoderException::TranscoderException(const TranscoderException &src)
   : Exception(src) {
}

TranscoderException& TranscoderException::operator=(const TranscoderException& src) {
     Exception::operator=(src);
     return *this;
}

std::string TranscoderException::formatMessage(log4cxx_status_t) {
     return "Transcoder exception";
}


MutexException::MutexException(log4cxx_status_t stat)
     : Exception(formatMessage(stat)) {
}

MutexException::MutexException(const MutexException &src)
     : Exception(src) {
}

MutexException& MutexException::operator=(const MutexException& src) {
      Exception::operator=(src);
      return *this;
}

std::string MutexException::formatMessage(log4cxx_status_t stat) {
      std::string s("Mutex exception: stat = ");
      Pool p;
      StringHelper::toString(stat, p, s);
      return s;
}

ConditionException::ConditionException(log4cxx_status_t stat)
     : Exception(formatMessage(stat)) {
}

ConditionException::ConditionException(const ConditionException &src)
     : Exception(src) {
}

ConditionException& ConditionException::operator=(const MutexException& src) {
      Exception::operator=(src);
      return *this;
}

std::string ConditionException::formatMessage(log4cxx_status_t stat) {
      std::string s("Condition exception: stat = ");
      Pool p;
      StringHelper::toString(stat, p, s);
      return s;
}

ThreadException::ThreadException(log4cxx_status_t stat)
     : Exception(formatMessage(stat)) {
}

ThreadException::ThreadException(const ThreadException &src)
      : Exception(src) {
}

ThreadException& ThreadException::operator=(const ThreadException& src) {
       Exception::operator=(src);
       return *this;
}

std::string ThreadException::formatMessage(log4cxx_status_t stat) {
       std::string s("Thread exception: stat = ");
       Pool p;
       StringHelper::toString(stat, p, s);
       return s;
}

IllegalMonitorStateException::IllegalMonitorStateException(const std::string& msg1)
      : Exception(msg1) {
}

IllegalMonitorStateException::IllegalMonitorStateException(const IllegalMonitorStateException& src)
      : Exception(src) {
}

IllegalMonitorStateException& IllegalMonitorStateException::operator=(const IllegalMonitorStateException& src) {
       Exception::operator=(src);
       return *this;
}

InstantiationException::InstantiationException(const std::string& msg1)
      : Exception(msg1) {
}

InstantiationException::InstantiationException(const InstantiationException& src)
       : Exception(src) {
}

InstantiationException& InstantiationException::operator=(const InstantiationException& src) {
        Exception::operator=(src);
        return *this;
}

ClassNotFoundException::ClassNotFoundException(const LogString& className)
    : Exception(formatMessage(className)) {
}

ClassNotFoundException::ClassNotFoundException(const ClassNotFoundException& src)
     : Exception(src) {
}


ClassNotFoundException& ClassNotFoundException::operator=(const ClassNotFoundException& src) {
      Exception::operator=(src);
      return *this;
}

std::string ClassNotFoundException::formatMessage(const LogString& className) {
      std::string s("Class not found: ");
      Transcoder::encode(className, s);
      return s;
}


NoSuchElementException::NoSuchElementException()
     : Exception("No such element") {
}

NoSuchElementException::NoSuchElementException(const NoSuchElementException& src)
     : Exception(src) {
}

NoSuchElementException& NoSuchElementException::operator=(const NoSuchElementException& src) {
      Exception::operator=(src);
      return *this;
}


IllegalStateException::IllegalStateException()
     : Exception("Illegal state") {
}

IllegalStateException::IllegalStateException(const IllegalStateException& src)
     : Exception(src) {
}

IllegalStateException& IllegalStateException::operator=(const IllegalStateException& src) {
      Exception::operator=(src);
      return *this;
}
