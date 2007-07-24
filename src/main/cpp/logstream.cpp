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
#include <log4cxx/stream.h>
#include <log4cxx/helpers/transcoder.h>

#if LOG4CXX_HAS_WCHAR_T
log4cxx::logstream& operator<<(
  ::log4cxx::logstream& lhs,
  const char* rhs) {
  LOG4CXX_DECODE_CHAR(tmp, rhs);
  LOG4CXX_ENCODE_WCHAR(msg, tmp);
  lhs.getStream() << msg;
  return lhs;
}
#else
log4cxx::logstream& operator<<(
  ::log4cxx::logstream& lhs,
  const char* rhs) {
  LOG4CXX_DECODE_CHAR(tmp, rhs);
  LOG4CXX_ENCODE_CHAR(msg, tmp);
  lhs.getStream() << msg;
  return lhs;
}
#endif

#if LOG4CXX_HAS_WCHAR_T
log4cxx::logstream& operator<<(
  ::log4cxx::logstream& lhs,
  const ::log4cxx::LogString& rhs) {
  LOG4CXX_DECODE_CHAR(tmp, rhs);
  LOG4CXX_ENCODE_WCHAR(msg, tmp);
  lhs.getStream() << msg;
  return lhs;
}
#else
log4cxx::logstream& operator<<(
  ::log4cxx::logstream& lhs,
  const ::log4cxx::LogString& rhs) {
  LOG4CXX_DECODE_CHAR(tmp, rhs);
  LOG4CXX_ENCODE_CHAR(msg, tmp);
  lhs.getStream() << msg;
  return lhs;
}
#endif

::log4cxx::logstream& operator<<(
   ::log4cxx::logstream& lhs,
   const ::log4cxx::spi::LocationInfo& rhs) {
   lhs.setLocation(rhs);
   return lhs;
}


::log4cxx::logstream& operator<<(
   ::log4cxx::logstream& lhs,
   const ::log4cxx::spi::LocationFlush& rhs) {
   lhs.flush(rhs);
   return lhs;
}

::log4cxx::logstream& operator<<(
   ::log4cxx::logstream& lhs,
   const ::log4cxx::LevelPtr& rhs) {
   lhs.setLevel(rhs);
   return lhs;
}


::log4cxx::logstream& operator<<(
   ::log4cxx::logstream& lhs,
   ::std::ios_base& (*manip)(::std::ios_base&)) {
     (*manip)(lhs);
   return lhs;
}
