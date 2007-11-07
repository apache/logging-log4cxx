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

#ifndef _LOG4CXX_STREAM_H
#define _LOG4CXX_STREAM_H

#include <log4cxx/logger.h>
#include <sstream>
#include <log4cxx/spi/location/locationinfo.h>

namespace log4cxx
{
        /**
         *   Base class for the basic_logstream template which attempts
         *   to emulate std::basic_ostream but attempts to short-circuit
         *   unnecessary operations.
         *
         *   The logstream has a logger and level that are used for logging
         *   requests.  The level of the stream is compared against the 
         *   current level of the logger to determine if the request should be processed.
         */
        class LOG4CXX_EXPORT logstream_base {
        public:
             /**
              *  Create new instance.
              *  @param logger logger logger used in log requests.
              *  @level level indicates level that will be used in log requests.  Can
              *      be modified later by inserting a level or calling setLevel.
              */
             logstream_base(const log4cxx::LoggerPtr& logger,
                 const log4cxx::LevelPtr& level);
             /**
              *  Destructor.
              */
             virtual ~logstream_base();
             /**
              *  Insertion operator for std::fixed and similar manipulators.
              */
             logstream_base& operator<<(std::ios_base& (*manip)(std::ios_base&));
             /**
              *  Insertion operator for logstream_base::log.
              */
             logstream_base& operator<<(logstream_base& (*manip)(logstream_base&));
             /**
              *   Insertion operator for level.
              */
             logstream_base& operator<<(const log4cxx::LevelPtr& level);
             /**
              *   Insertion operator for location.
              */
             logstream_base& operator<<(const log4cxx::spi::LocationInfo& location);

             /**
              *   get precision.
              */
             int precision();
             /**
              *   get width.
              */
             int width();
             /**
              *   set precision.  This should be used in preference to inserting an std::setprecision(n)
              *   since the other requires construction of an STL stream which may be expensive.
              */
             int precision(int newval);
             /**
              *   set width.  This should be used in preference to inserting an std::setw(n)
              *   since the other requires construction of an STL stream which may be expensive.
              */
             int width(int newval);
             /**
              *   Get fill character.
              */
             int fill();
             /**
              *  Set fill character.
              */
             int fill(int newval);
             
             /**
              *   Set flags. see std::ios_base.
              */
             std::ios_base::fmtflags flags(std::ios_base::fmtflags newflags);
             /**
              *   Set flags. see std::ios_base.
              */
             std::ios_base::fmtflags setf(std::ios_base::fmtflags newflags, std::ios_base::fmtflags mask);
             /**
              *   Set flags. see std::ios_base.
              */
             std::ios_base::fmtflags setf(std::ios_base::fmtflags newflags);
             
             
             /**
              *  log manipulator.
              */
             static logstream_base& log(logstream_base&);
             
             /**
              *   log operation.
              */
             void log();
             
             /**
              * Set the level.
              * @param level level
              */
              void setLevel(const LevelPtr& level);
              /**
               *  Returns true if the current level is the same or high as the 
               *  level of logger at time of construction or last setLevel.
               */
              inline bool isEnabled() const {
                 return enabled;
              }

              /**
               *  Returns if logger is currently enabled for the specified level.
               */
              bool isEnabledFor(const LevelPtr& level) const;

              /**
               *  Sets the location for subsequent log requests.
               */
              void setLocation(const log4cxx::spi::LocationInfo& location);

              /**
               *  Sets the state of the embedded stream (if any)
               *     to the state of the formatting info.
               *   @param os stream to receive formatting info.
               *   @param fillchar receives fill charater.
               *   @return true if fill character was specified.     
               */
              bool set_stream_state(std::ios_base& os, int& fillchar);

        protected:
              /**
               *   Dispatches the pending log request.
               */
              virtual void log(LoggerPtr& logger,
                               const LevelPtr& level,
                               const log4cxx::spi::LocationInfo& location) = 0;
              /**
               *   Erase any content in the message construction buffer.
               */
              virtual void erase() = 0;
              /**
               *   Copy state of embedded stream (if any)
               *      to value and mask instances of std::ios_base
               *      and return fill character value.
               */
              virtual void get_stream_state(std::ios_base& base,
                                            std::ios_base& mask,
                                            int& fill,
                                            bool& fillSet) const = 0;
              virtual void refresh_stream_state() = 0;
             
        private:
            /**
             *   prevent copy constructor.
             */
            logstream_base(logstream_base&);
            /**
             *   prevent copy operatpr.
             */
            logstream_base& operator=(logstream_base&);
            /**
             *   Minimal extension of std::ios_base to allow creation
             *     of embedded IO states.
             */
            class logstream_ios_base : public std::ios_base {
            public:
                logstream_ios_base(std::ios_base::fmtflags initval, 
                    int initsize) {
                    flags(initval);
                    precision(initsize);
                    width(initsize);
                    
                }
            } initset, initclear;
            /**
             *   fill character.
             */
            int fillchar;
            /**
             *   true if fill character is set.
             */
            bool fillset;
            /**
             *   true if assigned level was same or higher than level of associated logger.
             */
            bool enabled;
            /**
             *   associated logger.
             */
            log4cxx::LoggerPtr logger;
            /**
             *   associated level.
             */
            log4cxx::LevelPtr level;
            /**
             *   associated level.
             */
            log4cxx::spi::LocationInfo location;
        };
        
        
        /**
         *  Template for a STL-like stream API for log4cxx.  Instances of log4cxx::basic_logstream
         *  are emphatically not for use by multiple threads and in general should be short-lived
         *  function scoped objects.  Using log4cxx::basic_logstream as a class member or 
         *  static instance should be avoided in the same manner as you would avoid placing a std::ostringstream
         *  in those locations.  Insertion operations are generally short-circuited if the 
         *  level for the stream is not the same of higher that the level of the associated logger.
         */
        template <class Ch>
        class LOG4CXX_EXPORT basic_logstream : public logstream_base {
        public:
            /**
             *   Constructor.
             */
             inline basic_logstream(const log4cxx::LoggerPtr& logger,
                 const log4cxx::LevelPtr& level) : logstream_base(logger, level), stream(0) {
             }
             
            /**
             *   Constructor.
             */
             inline basic_logstream(const Ch* loggerName, 
                const log4cxx::LevelPtr& level) : logstream_base(log4cxx::Logger::getLogger(loggerName), level), stream(0) {
             }

            /**
             *   Constructor.
             */
             inline basic_logstream(const std::basic_string<Ch>& loggerName, 
                const log4cxx::LevelPtr& level) : logstream_base(log4cxx::Logger::getLogger(loggerName), level), stream(0) {
             }
             
             inline ~basic_logstream() {
             }
             
             /**
              *   Insertion operator for std::fixed and similar manipulators.
              */
             inline basic_logstream& operator<<(std::ios_base& (*manip)(std::ios_base&)) {
                logstream_base::operator<<(manip);
                return *this;
            }
            
             /**
              *   Insertion operator for logstream_base::log.
              */
            inline basic_logstream& operator<<(logstream_base& (*manip)(logstream_base&)) {
                logstream_base::operator<<(manip);
                return *this;
            }
            
            /**
             *   Insertion operator for level.
             */
            inline basic_logstream& operator<<(const log4cxx::LevelPtr& level) {
                 logstream_base::operator<<(level);
                 return *this;
            }
            /**
             *   Insertion operator for location.
             */
            inline basic_logstream& operator<<(const log4cxx::spi::LocationInfo& location) {
                 logstream_base::operator<<(location);
                 return *this;
            }
            
            
            /**
             *  Template to allow any class with an std::basic_ostream inserter
             *    to be applied to this class.
             */
            template <class V>
            inline basic_logstream& operator<<(const V& val) {
                 if (LOG4CXX_UNLIKELY(isEnabled())) {
                     std::basic_ostream<Ch>& os = *this;
                     os << val;
                 }
                 return *this;
            }
            

            /**
             *   Cast operator to provide access to embedded std::basic_ostream.
             */
            inline operator std::basic_ostream<Ch>&() {
                if (stream == 0) {
                    stream = new std::basic_stringstream<Ch>();
                    refresh_stream_state();
                }
                return *stream;
            }
            
        protected:
              /**
               *   {@inheritDoc}
               */
              virtual void log(LoggerPtr& logger,
                               const LevelPtr& level,
                               const log4cxx::spi::LocationInfo& location) {
                    if (stream != 0) {
                        std::basic_string<Ch> msg = stream->str();
                        if (!msg.empty()) {
                            logger->log(level, msg, location);
                        }
                    }
              }
              
              /**
               *   {@inheritDoc}
               */
              virtual void erase() {
                  if (stream != 0) {
                      std::basic_string<Ch> emptyStr;
                      stream->str(emptyStr);
                  }
              }
              
              /**
               *   {@inheritDoc}
               */
              virtual void get_stream_state(std::ios_base& base,
                                            std::ios_base& mask,
                                            int& fill,
                                            bool& fillSet) const {
                  if (stream != 0) {
                      std::ios_base::fmtflags flags = stream->flags();
                      base.flags(flags);
                      mask.flags(flags);
                      int width = stream->width();
                      base.width(width);
                      mask.width(width);
                      int precision = stream->precision();
                      base.precision(precision);
                      mask.precision(precision);
                      fill = stream->fill();
                      fillSet = true;
                  }
              }
              /**
               *   {@inheritDoc}
               */
              virtual void refresh_stream_state() {
                if (stream != 0) {
                    int fillchar;
                    if(logstream_base::set_stream_state(*stream, fillchar)) {
                        stream->fill(fillchar);
                    }
                }
             }
              
            
        private:
            std::basic_stringstream<Ch>* stream;
             
        };
        
        typedef basic_logstream<char> logstream;
#if LOG4CXX_HAS_WCHAR_T        
        typedef basic_logstream<wchar_t> wlogstream;
#endif


}  // namespace log4cxx


#if !defined(LOG4CXX_ENDMSG)
#define LOG4CXX_ENDMSG LOG4CXX_LOCATION << log4cxx::logstream_base::log;
#endif


#endif //_LOG4CXX_STREAM_H
