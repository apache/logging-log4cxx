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

using namespace log4cxx;

logstream_base::logstream_base(const LoggerPtr& log,
     const LevelPtr& lvl) : initset((std::ios_base::fmtflags) -1, 1), 
     initclear((std::ios_base::fmtflags) 0, 0), logger(log), level(lvl), location(), fillchar(0), fillset(false) {
     enabled = logger->isEnabledFor(level);
}

logstream_base::~logstream_base() {
}

logstream_base& logstream_base::operator<<(std::ios_base& (*manip)(std::ios_base&)) {
    get_stream_state(initclear, initset, fillchar, fillset);
    (*manip)(initset);
    (*manip)(initclear);
    refresh_stream_state();
    return *this;
}

logstream_base& logstream_base::operator<<(logstream_base& (*manip)(logstream_base&)) {
    (*manip)(*this);
    return *this;
}

logstream_base& logstream_base::operator<<(const LevelPtr& level) {
    setLevel(level);
    return *this;
}

bool logstream_base::set_stream_state(std::ios_base& dest, int& dstchar) {
     std::ios_base::fmtflags setval = initset.flags();
     std::ios_base::fmtflags clrval = initclear.flags();
     std::ios_base::fmtflags mask = setval ^ (~clrval);
     dest.setf(clrval, mask);
     if (initset.precision() == initclear.precision()) {
         dest.precision(initset.precision());
     }
     if (initset.width() == initclear.width()) {
         dest.width(initset.width());
     }
     dstchar = fillchar;
     return fillset;
}

logstream_base& logstream_base::log(logstream_base& stream) {
     stream.log();
     return stream;
}

void logstream_base::log() {
     if (isEnabled()) {
         log(logger, level, location);
     }
     erase();
}


int log4cxx::logstream_base::precision(int p) {
    get_stream_state(initclear, initset, fillchar, fillset);
    initset.precision(p);
    int oldVal = initclear.precision(p);
    refresh_stream_state();
    return oldVal;
}

int log4cxx::logstream_base::precision() {
    get_stream_state(initclear, initset, fillchar, fillset);
   return initclear.precision();
}

int log4cxx::logstream_base::width(int w) {
    get_stream_state(initclear, initset, fillchar, fillset);
    initset.width(w);
    int oldVal = initclear.width(w);
    refresh_stream_state();
    return oldVal;
}

int log4cxx::logstream_base::width()  {
    get_stream_state(initclear, initset, fillchar, fillset);
    return initclear.width();
}

int log4cxx::logstream_base::fill(int newfill) {
    get_stream_state(initclear, initset, fillchar, fillset);
    int oldfill = fillchar;
    fillchar = newfill;
    fillset = true;
    refresh_stream_state();
    return oldfill;
}

int logstream_base::fill()  {
    get_stream_state(initclear, initset, fillchar, fillset);
    return fillchar;
}

std::ios_base::fmtflags logstream_base::flags(std::ios_base::fmtflags newflags) {
    get_stream_state(initclear, initset, fillchar, fillset);
    initset.flags(newflags);
    std::ios_base::fmtflags oldVal = initclear.flags(newflags);
    refresh_stream_state();
    return oldVal;
}

std::ios_base::fmtflags logstream_base::setf(std::ios_base::fmtflags newflags, std::ios_base::fmtflags mask) {
    get_stream_state(initclear, initset, fillchar, fillset);
    initset.setf(newflags, mask);
    std::ios_base::fmtflags oldVal = initclear.setf(newflags, mask);
    refresh_stream_state();
    return oldVal;
}

std::ios_base::fmtflags logstream_base::setf(std::ios_base::fmtflags newflags) {
    get_stream_state(initclear, initset, fillchar, fillset);
    initset.setf(newflags);
    std::ios_base::fmtflags oldVal = initclear.setf(newflags);
    refresh_stream_state();
    return oldVal;
}
    


void logstream_base::setLevel(const ::log4cxx::LevelPtr& newlevel) {
    level = newlevel;
    bool oldLevel = enabled;
    enabled = logger->isEnabledFor(level);
    if (oldLevel != enabled) {
        erase();
    }
}

bool logstream_base::isEnabledFor(const ::log4cxx::LevelPtr& level) const {
    return logger->isEnabledFor(level);
}


void logstream_base::setLocation(const log4cxx::spi::LocationInfo& newlocation) {
    if (LOG4CXX_UNLIKELY(enabled)) {
        location = newlocation;
    }
}

logstream_base& logstream_base::operator<<(const log4cxx::spi::LocationInfo& newlocation) {
   setLocation(newlocation);
   return *this;
}

