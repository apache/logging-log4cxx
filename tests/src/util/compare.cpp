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

#include "compare.h"
#include <fstream>
#include <iostream>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/file.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/fileinputstream.h>
#include <log4cxx/helpers/inputstreamreader.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

bool Compare::compare(const File& file1, const File& file2)
{
    Pool pool;
    InputStreamPtr fileIn1 = new FileInputStream(file1);
    InputStreamReaderPtr reader1 = new InputStreamReader(fileIn1);
    LogString in1(reader1->read(pool));

    Pool pool2;
    InputStreamPtr fileIn2 = new FileInputStream(file2);
    InputStreamReaderPtr reader2 = new InputStreamReader(fileIn2);
    LogString in2(reader2->read(pool2));

    LogString back1(in1);
    LogString back2(in2);

    LogString s1;
    LogString s2;
        int lineCounter = 0;

        while (StringHelper::getline(in1, s1))
        {
                lineCounter++;

        if(!StringHelper::getline(in2, s2)) {
          s2.erase(s2.begin(), s2.end());
        }

        if (s1 != s2) {
            LogString msg(LOG4CXX_STR("Files ["));
            msg += file1.getName();
            msg += LOG4CXX_STR("] and [");
            msg += file2.getName();
            msg += LOG4CXX_STR("] differ on line ");
            msg += StringHelper::toString(lineCounter, pool);
            msg += LOG4CXX_EOL;
            msg += LOG4CXX_STR("One reads:  [");
            msg += s1;
            msg += LOG4CXX_STR("].") LOG4CXX_EOL;
            msg += LOG4CXX_STR("Other reads:[");
            msg += s2;
            msg += LOG4CXX_STR("].") LOG4CXX_EOL;
            emit(msg);

            outputFile(file1, back1, pool);
                        outputFile(file2, back2, pool);

                        return false;
                }
        }

        // the second file is longer
    if (StringHelper::getline(in2, s2)) {
        LogString msg(LOG4CXX_STR("File ["));
        msg += file2.getName();
        msg += LOG4CXX_STR("] longer than file [");
        msg += file1.getName();
        msg += LOG4CXX_STR("].") LOG4CXX_EOL;
        emit(msg);
                outputFile(file1, back1, pool);
                outputFile(file2, back2, pool);

                return false;
        }

        return true;
}

void Compare::outputFile(const File& file,
                        const LogString& contents,
                        log4cxx::helpers::Pool& pool)
{
        int lineCounter = 0;
        emit(LOG4CXX_STR("--------------------------------") LOG4CXX_EOL);
        LogString msg(LOG4CXX_STR("Contents of "));
        msg += file.getName();
        msg += LOG4CXX_STR(":") LOG4CXX_EOL;
        emit(msg);
        LogString in1(contents);
        LogString s1;

        while (StringHelper::getline(in1, s1))
        {
                lineCounter++;
                emit(StringHelper::toString(lineCounter, pool));

                if (lineCounter < 10)
                {
                        emit(LOG4CXX_STR("   : "));
                }
                else if (lineCounter < 100)
                {
                        emit(LOG4CXX_STR("  : "));
                }
                else if (lineCounter < 1000)
                {
                        emit(LOG4CXX_STR(" : "));
                }
                else
                {
                        emit(LOG4CXX_STR(": "));
                }
                emit(s1);
                emit(LOG4CXX_EOL);
        }
}

bool Compare::gzCompare(const File& file1, const File& file2)
{
    return false;
}


void Compare::emit(const std::string& s1) {
  std::cout << s1;
}

#if LOG4CXX_HAS_WCHAR_T
void Compare::emit(const std::wstring& s1) {
  std::wcout << s1;
}
#endif

