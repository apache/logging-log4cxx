/*
 * Copyright 2003,2004 The Apache Software Foundation.
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

#include <log4cxx/ndc.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/logger.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/xml/domconfigurator.h>
#include <apr_general.h>
#include <apr_pools.h>
#include <apr_time.h>
#include <iostream>

#define _T(str) str

using namespace log4cxx;
using namespace log4cxx::helpers;

int runLength;
int delay = -1;
/*
 A delay is applied after every <code>burstLen</code> log
 requests.  The default value of this constant is 100.  */
int burstLen = 100;
int DELAY_MULT = 1000/burstLen;

LoggerPtr logger = Logger::getLogger(_T("A0123456789.B0123456789.C0123456789"));

void Usage(const std::string& processName, const std::string& msg)
{
        std::cerr << msg << std::endl;
        std::cerr <<
                "Usage: " << processName
                << " confFile runLength [delay] [burstLen]" << std::endl
                << "       confFile is an XML configuration file and" << std::endl
                << "       runLength (integer) is the length of test loop." << std::endl
                << "       delay is the time in millisecs to wait every burstLen log requests." << std::endl;
        exit(EXIT_FAILURE);
}

class IllegalRunLengthException : public IllegalArgumentException {
   public:
   IllegalRunLengthException() throw() {}
   const char* what() const throw() {
     return "run Length must be greater than 0";
   }
};

void init(const std::string& configFile, const std::string& runLengthStr,
                  const std::string& delayStr, const std::string& burstLenStr)
{
        runLength = atoi(runLengthStr.c_str());
        if (runLength < 1)
        {
                throw IllegalRunLengthException();
        }
        if (!delayStr.empty())
        {
                delay = atoi(delayStr.c_str());
        }
        if (!burstLenStr.empty())
        {
                burstLen = atoi(burstLenStr.c_str());
                DELAY_MULT = 1000/burstLen;
        }

#ifdef LOG4CXX_HAVE_XML
        xml::DOMConfigurator::configure(configFile);
#endif
}

double NoDelayLoop(LoggerPtr logger, const std::string& msg)
{
    log4cxx_time_t before = apr_time_now();
    for(int i = 0; i < runLength; i++) {
        logger->info(msg, LOG4CXX_LOCATION);
    }
    log4cxx_time_t after = apr_time_now();
    return (after - before)/(runLength*1000);
}

double DelayedLoop(LoggerPtr logger, const std::string& msg)
{

    log4cxx_time_t before = apr_time_now();
    int j = 0;
    for(int i = 0; i < runLength; i++)
        {
                logger->info(msg, LOG4CXX_LOCATION);
                if(j++ == burstLen)
                {
                        j = 0;
                        try
                        {
                                apr_sleep(delay * 1000);
                        }
                        catch(Exception&)
                        {
                        }
                }

    }
    double actualTime = (apr_time_now()-before)/(runLength*1000);
    std::cout << "actual time: " << actualTime << std::endl;
    return (actualTime - delay*DELAY_MULT);
}

int main(int argc, const char* const argv[])
{
        apr_app_initialize(&argc, &argv, NULL);
        int ret = EXIT_SUCCESS;

        try
        {
                if(argc == 3)
                        init(argv[1], argv[2], "", "");
                else if(argc == 5)
                        init(argv[1], argv[2], argv[3], argv[4]);
                else
                        Usage(argv[0], "Wrong number of arguments.");


                NDC::push(_T("some context"));

                double delta;
                std::string msg = _T("ABCDEGHIJKLMNOPQRSTUVWXYZabcdeghijklmnopqrstuvwxyz1234567890");
                if(delay <= 0)
                {
                        delta = NoDelayLoop(logger, msg);
                }
                else
                {
                        delta = DelayedLoop(logger, msg);
                }

                std::cout << (int)delta << std::endl;

                LogManager::shutdown();
        }
        catch(Exception&)
        {
                ret = EXIT_FAILURE;
        }

        apr_terminate();

        return ret;
}
