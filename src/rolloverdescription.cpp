/*
 * Copyright 1999,2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 #include <log4cxx/rolling/rolloverdescription.h>

using namespace log4cxx;
using namespace log4cxx::rolling;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(RolloverDescription)


RolloverDescription::RolloverDescription() {
}

RolloverDescription::RolloverDescription(
    const LogString& activeFileName,
    const bool append,
    const ActionPtr& synchronous,
    const ActionPtr& asynchronous)
       : activeFileName(activeFileName),
         append(append),
         synchronous(synchronous),
         asynchronous(asynchronous) {
}

LogString RolloverDescription::getActiveFileName() const {
    return activeFileName;
}

bool RolloverDescription::getAppend() const {
    return append;
}

ActionPtr RolloverDescription::getSynchronous() const {
    return synchronous;
}

  /**
   * Action to be completed after close of current active log file
   * and before next rollover attempt, may be executed asynchronously.
   *
   * @return action, may be null.
   */
ActionPtr RolloverDescription::getAsynchronous() const {
    return asynchronous;
}
