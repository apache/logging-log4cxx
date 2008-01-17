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
#include <log4cxx/dailyrollingfileappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/rolling/rollingfileappender.h>
#include <log4cxx/rolling/timebasedrollingpolicy.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::rolling;

IMPLEMENT_LOG4CXX_OBJECT(DailyRollingFileAppender)



DailyRollingFileAppender::DailyRollingFileAppender()
    : rfa(new log4cxx::rolling::RollingFileAppender())
{
}


DailyRollingFileAppender::DailyRollingFileAppender(
  const LayoutPtr& layout,
  const LogString& filename,
  const LogString& datePattern1)
  : datePattern(datePattern1),
    rfa(new log4cxx::rolling::RollingFileAppender()) {
    rfa->setLayout(layout);
    rfa->setFile(filename);
    Pool p;
    activateOptions(p);
}

void DailyRollingFileAppender::addRef() const {
    ObjectImpl::addRef();
}

void DailyRollingFileAppender::releaseRef() const {
    ObjectImpl::releaseRef();
}

void DailyRollingFileAppender::setDatePattern(const LogString& pattern) {
   datePattern = pattern;
}

LogString DailyRollingFileAppender::getDatePattern() {
  return datePattern;
}

void DailyRollingFileAppender::activateOptions(log4cxx::helpers::Pool& pool) {
  TimeBasedRollingPolicyPtr policy = new TimeBasedRollingPolicy();
  LogString pattern(rfa->getFile());
  bool inLiteral = false;
  bool inPattern = false;

  for (size_t i = 0; i < datePattern.length(); i++) {
    if (datePattern[i] == 0x27 /* '\'' */) {
      inLiteral = !inLiteral;

      if (inLiteral && inPattern) {
        pattern.append(1, (logchar) 0x7D /* '}' */);
        inPattern = false;
      }
    } else {
      if (!inLiteral && !inPattern) {
        const logchar dbrace[] = { 0x25, 0x64, 0x7B, 0 }; // "%d{"
        pattern.append(dbrace);
        inPattern = true;
      }

      pattern.append(1, datePattern[i]);
    }
  }

  if (inPattern) {
    pattern.append(1, (logchar) 0x7D /* '}' */);
  }

  policy->setFileNamePattern(pattern);
  policy->activateOptions(pool);
  rfa->setTriggeringPolicy(policy);
  rfa->setRollingPolicy(policy);

  rfa->activateOptions(pool);
}

void DailyRollingFileAppender::addFilter(const log4cxx::spi::FilterPtr& newFilter) {
  rfa->addFilter(newFilter);
}

log4cxx::spi::FilterPtr DailyRollingFileAppender::getFilter() const {
  return rfa->getFilter();
}

void DailyRollingFileAppender::clearFilters() {
  rfa->clearFilters();
}

void DailyRollingFileAppender::close() {
  rfa->close();
}

bool DailyRollingFileAppender::isClosed() const {
  return false;
}

bool DailyRollingFileAppender::isActive() const {
  return true;
}

void DailyRollingFileAppender::doAppend(const log4cxx::spi::LoggingEventPtr& event,
   log4cxx::helpers::Pool& pool) {
  rfa->doAppend(event, pool);
}

LogString DailyRollingFileAppender::getName() const {
  return rfa->getName();
}

void DailyRollingFileAppender::setLayout(const LayoutPtr& layout) {
  rfa->setLayout(layout);
}

LayoutPtr DailyRollingFileAppender::getLayout() const {
  return rfa->getLayout();
}

void DailyRollingFileAppender::setName(const LogString& name) {
  rfa->setName(name);
}


void DailyRollingFileAppender::setFile(const LogString& file) {
  rfa->setFile(file);
}

bool DailyRollingFileAppender::getAppend() const {
  return rfa->getAppend();
}

LogString DailyRollingFileAppender::getFile() const {
  return rfa->getFile();
}

bool DailyRollingFileAppender::getBufferedIO() const {
  return rfa->getBufferedIO();
}

int DailyRollingFileAppender::getBufferSize() const {
  return rfa->getBufferSize();
}

void DailyRollingFileAppender::setAppend(bool flag) {
  rfa->setAppend(flag);
}

void DailyRollingFileAppender::setBufferedIO(bool bufferedIO) {
  rfa->setBufferedIO(bufferedIO);
}

void DailyRollingFileAppender::setBufferSize(int bufferSize) {
  rfa->setBufferSize(bufferSize);
}

void DailyRollingFileAppender::setOption(const LogString& option,
   const LogString& value) {
     if (StringHelper::equalsIgnoreCase(option,
                     LOG4CXX_STR("DATEPATTERN"), LOG4CXX_STR("datepattern"))) {
             setDatePattern(value);
     } else {
         rfa->setOption(option, value);
     }
}

void DailyRollingFileAppender::setErrorHandler(const spi::ErrorHandlerPtr& errorHandler) {
   rfa->setErrorHandler(errorHandler);
}

const spi::ErrorHandlerPtr& DailyRollingFileAppender::getErrorHandler() const {
  return rfa->getErrorHandler();
}

bool DailyRollingFileAppender::requiresLayout() const {
  return rfa->requiresLayout();
}



