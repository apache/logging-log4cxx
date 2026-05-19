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

#include <log4cxx/helpers/systemerrwriter.h>
#include <stdio.h>
#include <log4cxx/private/consolewriter_priv.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

IMPLEMENT_LOG4CXX_OBJECT(SystemErrWriter)

SystemErrWriter::SystemErrWriter()
{
}

SystemErrWriter::~SystemErrWriter()
{
}

void SystemErrWriter::close( LOG4CXX_CLOSE_WRITER_FORMAL_PARAMETERS )
{
}

void SystemErrWriter::flush( LOG4CXX_FLUSH_WRITER_FORMAL_PARAMETERS )
{
	fflush(stderr);
}

void SystemErrWriter::write( LOG4CXX_WRITE_WRITER_FORMAL_PARAMETERS )
{
	helpers::writeToConsole(str, stderr);
}

#if LOG4CXX_ABI_VERSION <= 15
void SystemErrWriter::write(const LogString& str)
{
	helpers::writeToConsole(str, stderr);
}

void SystemErrWriter::flush()
{
	fflush(stderr);
}
#endif
