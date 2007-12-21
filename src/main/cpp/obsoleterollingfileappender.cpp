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
#include <log4cxx/rollingfileappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/rolling/rollingfileappender.h>
#include <log4cxx/rolling/sizebasedtriggeringpolicy.h>
#include <log4cxx/rolling/fixedwindowrollingpolicy.h>


using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

namespace log4cxx {
    class ClassRollingFileAppender : public Class 
    {
    public:
        ClassRollingFileAppender() : helpers::Class() {}
        virtual LogString getName() const {
            return LOG4CXX_STR("org.apache.log4j.RollingFileAppender");
        }
        virtual ObjectPtr newInstance() const {
            return new RollingFileAppender();
        }
    };
}

const log4cxx::helpers::Class& RollingFileAppender::getClass() const { return getStaticClass(); }
const log4cxx::helpers::Class& RollingFileAppender::getStaticClass() { 
   static ClassRollingFileAppender theClass;
   return theClass;
}                                                        
const log4cxx::helpers::ClassRegistration& RollingFileAppender::registerClass() {
    static log4cxx::helpers::ClassRegistration classReg(RollingFileAppender::getStaticClass);
    return classReg;
}
namespace log4cxx { namespace classes {
const log4cxx::helpers::ClassRegistration& ObsoleteRollingFileAppenderRegistration = 
        RollingFileAppender::registerClass();
} }



RollingFileAppender::RollingFileAppender()
   : maxFileSize(10*1024*1024), maxBackupIndex(1),
     rfa(new log4cxx::rolling::RollingFileAppender()) {
}

RollingFileAppender::RollingFileAppender(
  const LayoutPtr& layout,
  const LogString& filename,
  bool append)
  : maxFileSize(10*1024*1024), maxBackupIndex(1),
    rfa(new log4cxx::rolling::RollingFileAppender()) {
  rfa->setLayout(layout);
  rfa->setFile(filename);
  rfa->setAppend(append);
  Pool pool;
  activateOptions(pool);
}

RollingFileAppender::RollingFileAppender(const LayoutPtr& layout,
   const LogString& filename)
   : maxFileSize(10*1024*1024), maxBackupIndex(1),
     rfa(new log4cxx::rolling::RollingFileAppender()) {
  rfa->setLayout(layout);
  rfa->setFile(filename);
  Pool pool;
  activateOptions(pool);
}

RollingFileAppender::~RollingFileAppender() {
}

void RollingFileAppender::setOption(const LogString& option,
        const LogString& value)
{
        if (StringHelper::equalsIgnoreCase(option,
                        LOG4CXX_STR("MAXFILESIZE"), LOG4CXX_STR("maxfilesize"))
                || StringHelper::equalsIgnoreCase(option,
                        LOG4CXX_STR("MAXIMUMFILESIZE"), LOG4CXX_STR("maximumfilesize")))
        {
                setMaxFileSize(value);
        }
        else if (StringHelper::equalsIgnoreCase(option,
                        LOG4CXX_STR("MAXBACKUPINDEX"), LOG4CXX_STR("maxbackupindex"))
                || StringHelper::equalsIgnoreCase(option,
                        LOG4CXX_STR("MAXIMUMBACKUPINDEX"), LOG4CXX_STR("maximumbackupindex")))
        {
                maxBackupIndex = StringHelper::toInt(value);
        }
        else
        {
                rfa->setOption(option, value);
        }
}


int RollingFileAppender::getMaxBackupIndex() const {
  return maxBackupIndex;
}

long RollingFileAppender::getMaximumFileSize() const {
  return maxFileSize;
}

void RollingFileAppender::setMaxBackupIndex(int maxBackups) {
  maxBackupIndex = maxBackups;
}

void RollingFileAppender::setMaximumFileSize(int maxFileSize1) {
  RollingFileAppender::maxFileSize = maxFileSize1;
}

void RollingFileAppender::setMaxFileSize(const LogString& value) {
  maxFileSize = OptionConverter::toFileSize(value, maxFileSize + 1);
}

void RollingFileAppender::activateOptions(Pool& pool) {
  log4cxx::rolling::SizeBasedTriggeringPolicyPtr trigger(
      new log4cxx::rolling::SizeBasedTriggeringPolicy());
  trigger->setMaxFileSize(maxFileSize);
  trigger->activateOptions(pool);
  rfa->setTriggeringPolicy(trigger);

  log4cxx::rolling::FixedWindowRollingPolicyPtr rolling(
      new log4cxx::rolling::FixedWindowRollingPolicy());
  rolling->setMinIndex(1);
  rolling->setMaxIndex(maxBackupIndex);
  rolling->setFileNamePattern(rfa->getFile() + LOG4CXX_STR(".%i"));
  rolling->activateOptions(pool);
  rfa->setRollingPolicy(rolling);

  rfa->activateOptions(pool);
}


void RollingFileAppender::addFilter(const FilterPtr& newFilter) {
  rfa->addFilter(newFilter);
}

FilterPtr RollingFileAppender::getFilter() const {
  return rfa->getFilter();
}

void RollingFileAppender::clearFilters() {
  rfa->clearFilters();
}

void RollingFileAppender::close() {
  rfa->close();
}

bool RollingFileAppender::isClosed() const {
  return false;
}

bool RollingFileAppender::isActive() const {
//  return rfa->isActive();
  return true;
}

void RollingFileAppender::doAppend(const LoggingEventPtr& event, Pool& p) {
  rfa->doAppend(event, p);
}

LogString RollingFileAppender::getName() const {
  return rfa->getName();
}

void RollingFileAppender::setLayout(const LayoutPtr& layout) {
  rfa->setLayout(layout);
}

LayoutPtr RollingFileAppender::getLayout() const {
  return rfa->getLayout();
}

void RollingFileAppender::setName(const LogString& name) {
  rfa->setName(name);
}

void RollingFileAppender::setFile(const LogString& file) {
  rfa->setFile(file);
}

bool RollingFileAppender::getAppend() const {
  return rfa->getAppend();
}

void RollingFileAppender::setBufferedIO(bool bufferedIO) {
  rfa->setBufferedIO(bufferedIO);
}

void RollingFileAppender::setBufferSize(int bufferSize) {
  rfa->setBufferSize(bufferSize);
}


void RollingFileAppender::rollOver() {
      Pool p;
      rfa->rollover(p);
}

bool RollingFileAppender::requiresLayout() const {
     return true;
}

