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

#include <log4cxx/rollingfileappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(RollingFileAppender)

RollingFileAppender::RollingFileAppender()
: maxFileSize(10*1024*1024), maxBackupIndex(1)
{
}


RollingFileAppender::RollingFileAppender(const LayoutPtr& layout,
     const File& fileName, bool append)
: FileAppender(layout, fileName, append),
maxFileSize(10*1024*1024), maxBackupIndex(1)
{
}

RollingFileAppender::RollingFileAppender(const LayoutPtr& layout,
   const File& fileName)
   : FileAppender(layout, fileName),
maxFileSize(10*1024*1024), maxBackupIndex(1)
{
}

RollingFileAppender::~RollingFileAppender()
{
        finalize();
}

// synchronization not necessary since doAppend is alreasy synched
void RollingFileAppender::rollOver()
{
  //   TODO
#if 0
        LogLog::debug(LOG4CXX_STR("rolling over count="));
        LogLog::debug(((LogString) LOG4CXX_STR("maxBackupIndex=")) + StringHelper::toInt(maxBackupIndex));

        // close and reset the current file
        apr_file_close(ofs);
        ofs = NULL;

        // If maxBackups <= 0, then there is no file renaming to be done.
        if(maxBackupIndex > 0)
        {
                // Delete the oldest file, to keep Windows happy.
                StringBuffer file;
                file << fileName << _T(".") << maxBackupIndex;
                USES_CONVERSION;
                remove(T2A(file.str().c_str()));

                // Map {(maxBackupIndex - 1), ..., 2, 1} to {maxBackupIndex, ..., 3, 2}
                for (int i = maxBackupIndex - 1; i >= 1; i--)
                {
                        StringBuffer file;
                        StringBuffer target;

                        file << fileName << _T(".") << i;
                        target << fileName << _T(".") << (i + 1);
                        LogLog::debug(_T("Renaming file ") + file.str() + _T(" to ") + target.str());
                        std::string aFileName = T2A(file.str().c_str());
                        std::string aTarget = T2A(target.str().c_str());
                        rename(aFileName.c_str(), aTarget.c_str());
                }

                // Rename fileName to fileName.1
                StringBuffer target;
                target << fileName << _T(".") << 1;

                LogLog::debug(_T("Renaming file ") + fileName + _T(" to ") + target.str());
                std::string aFileName = T2A(fileName.c_str());
                std::string aTarget = T2A(target.str().c_str());
                rename(aFileName.c_str(), aTarget.c_str());
        }

        // Open the current file up again in truncation mode
        USES_CONVERSION;
        ofs.open(T2A(fileName.c_str()), std::ios::out|std::ios::trunc);
        if(!ofs.is_open())
        {
                LogLog::error(_T("Unable to open file: ") + fileName);
        }
#endif
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
                FileAppender::setOption(option, value);
        }
}

void RollingFileAppender::subAppend(const char* encoded, log4cxx_size_t size, Pool& p) {
  FileAppender::subAppend(encoded, size, p);
}

