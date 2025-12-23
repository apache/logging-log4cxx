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

#include "transformer.h"
#include <log4cxx/file.h>
#include <log4cxx/helpers/transcoder.h>
#include <assert.h>
#include <iostream>
#include <filesystem>
#include <fstream>

using namespace log4cxx;
using namespace log4cxx::helpers;

void Transformer::transform(const File& in, const File& out,
	const std::vector<Filter*>& filters)
{
	log4cxx::Filter::PatternList patterns;

	for (std::vector<Filter*>::const_iterator iter = filters.begin();
		iter != filters.end();
		iter++)
	{

		const log4cxx::Filter::PatternList& thesePatterns = (*iter)->getPatterns();

		for (log4cxx::Filter::PatternList::const_iterator pattern = thesePatterns.begin();
			pattern != thesePatterns.end();
			pattern++)
		{
			patterns.push_back(*pattern);
		}
	}

	transform(in, out, patterns);
}

void Transformer::transform(const File& in, const File& out,
	const Filter& filter)
{
	transform(in, out, filter.getPatterns());
}


void Transformer::copyFile(const File& in, const File& out)
{
    bool stat = std::filesystem::copy_file(in.getPath(), out.getPath());
    assert(stat);
}

void Transformer::createSedCommandFile(const std::string& regexName,
    const log4cxx::Filter::PatternList& patterns)
{
    std::fstream regexFile(regexName, std::ios::out | std::ios::binary | std::ios::trunc);
    assert(regexFile.is_open());

	std::string tmp;

	auto sedSanitizer = [] (const std::string& in, const std::string& sedSeparator = "Q")
	{
		std::string ret = in;
		std::string replaceTo = "\\" + sedSeparator;
		size_t pos = 0;

		while((pos = ret.find(sedSeparator, pos)) != std::string::npos)
		{
			ret.replace(pos, sedSeparator.length(), replaceTo);
			pos += replaceTo.length();
		}

		return ret;
	};

	for (log4cxx::Filter::PatternList::const_iterator iter = patterns.begin();
		iter != patterns.end();
		iter++)
	{
		tmp = "sQ";
		tmp.append(sedSanitizer(iter->first));
		tmp.append(1, 'Q');
		tmp.append(sedSanitizer(iter->second));
        tmp.append("Qg\n");
        regexFile << tmp.c_str();
    }
}

void Transformer::transform(const File& in, const File& out,
	const log4cxx::Filter::PatternList& patterns)
{
    copyFile(in, out);

    if(patterns.size() > 0)
    {
		//
		//   write the regex's to a temporary file since they
		//      may get mangled if passed as parameters
		//
		std::string regexName;
		Transcoder::encode(in.getPath(), regexName);
		regexName.append(".sed");
        createSedCommandFile(regexName, patterns);

        std::vector<std::string> exec_args;
        exec_args.push_back("sed");
        exec_args.push_back("-i"); // edit in-place
        exec_args.push_back("-f");
        exec_args.push_back(regexName);
        exec_args.push_back(out.getPath());

        std::string sed_command;
        for(const std::string& str : exec_args){
            sed_command.append(str);
            sed_command.append(" ");
        }

        // execute sed using the default shell on the system
        int status = std::system(sed_command.c_str());
        assert(status == 0);
	}


}
