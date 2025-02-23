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

#include <fuzzer/FuzzedDataProvider.h>
#include <log4cxx/xml/domconfigurator.h>

namespace
{
	const size_t MaximumFileByteCount = 100000;
}

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::xml;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	char filename[9] = "conf.xml";

	FILE *fp = fopen(filename, "wb");
	if (!fp) {
		return 0;
	}
	fwrite(data, std::min(size, MaximumFileByteCount), 1, fp);
	fclose(fp);
	DOMConfigurator::configure(filename);
	return 0;
}
