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

#include "transformer.h"
#include <log4cxx/file.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx;
using namespace log4cxx::helpers;


void Transformer::transform(const File& in, const File& out,
	const std::vector<Filter *>& filters) throw(UnexpectedFormatException)
{
        Pool pool;
	LogString line;
	LogString input(in.read(pool));
        LogString output;

	while (StringHelper::getline(input, line))
	{
		for (std::vector<Filter *>::size_type i = 0; i < filters.size(); i++)
		{
			line = filters[i]->filter(line);
		}
		if (!line.empty())
		{
			output.append(line);
                        output.append(1, '\n');
		}
	}
        out.write(output, pool);
}

void Transformer::transform(const File& in, const File& out,
	const Filter& filter) throw(UnexpectedFormatException)
{
        Pool pool;
        LogString line;
        LogString input(in.read(pool));
        LogString output;

	while (StringHelper::getline(input, line))
	{
		line = filter.filter(line);
		output.append(line);
                output.append(1, '\n');
	}
        out.write(output, pool);

}

