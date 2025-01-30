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

#include "stdint.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/rolling/rollingfileappender.h>
#include <log4cxx/rolling/timebasedrollingpolicy.h>
#include <log4cxx/logmanager.h>

#define DATE_PATTERN            "yyyy-MM-dd_HH_mm_ss"
#define PATTERN_LAYOUT          LOG4CXX_STR("%c{1} - %m%n")

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::rolling;

// A fuzzer for TimeBasedRollingPolicy
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Set up logger
    Pool            pool;
    PatternLayoutPtr         layout( new PatternLayout(PATTERN_LAYOUT));
    RollingFileAppenderPtr  rfa(    new RollingFileAppender());
    rfa->setAppend(fdp.ConsumeBool());
    rfa->setLayout(layout);

    TimeBasedRollingPolicyPtr tbrp = TimeBasedRollingPolicyPtr(new TimeBasedRollingPolicy());
    bool usegz = fdp.ConsumeBool();
    if(usegz) {
           tbrp->setFileNamePattern(LogString(LOG4CXX_STR("fuzz-%d{" DATE_PATTERN "}.gz")));
    } else {
           tbrp->setFileNamePattern(LogString(LOG4CXX_STR("fuzz-%d{" DATE_PATTERN "}.zip")));
    }
    rfa->setFile(LOG4CXX_STR(LOG4CXX_STR("test.log")));
    
    tbrp->activateOptions(pool);
    rfa->setRollingPolicy(tbrp);
    rfa->activateOptions(pool);
    rfa->setBufferedSeconds(fdp.ConsumeIntegral<int>());
    rfa->activateOptions(pool);
    LoggerPtr logger = LogManager::getLogger("org.apache.log4j.TimeBasedRollingTest");
    logger->addAppender(rfa);
    
    // Log and rollover
    for (int i = 0; i < 10; i++)
    {
            if (i == 4 || i == 9)
            {
                rfa->rollover(pool);
            }

            LOG4CXX_DEBUG(logger, fdp.ConsumeRandomLengthString());
    }

    // Cleanup
    logger->removeAppender(rfa);
    rfa->close();
    LogManager::shutdown();
    std::remove("test.log");

    return 0;
}
