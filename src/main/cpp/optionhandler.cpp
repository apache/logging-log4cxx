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
#include <log4cxx/spi/optionhandler.h>
#include <log4cxx/helpers/pool.h>

using namespace LOG4CXX_NS;

#if LOG4CXX_ABI_VERSION <= 15
void spi::OptionHandler::activateOptions()
{
	// Ensure any ABI 15 overriden activateOptions is invoked
	helpers::Pool p;
	activateOptions(p);
}
#else
void spi::OptionHandler::activateOptions(helpers::Pool&)
{
	// Redirect to the ABI 16 activateOptions
	activateOptions();
}
#endif
