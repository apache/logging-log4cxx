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

#include "../logunit.h"

#include <apr_thread_proc.h>
#include <apr_env.h>
#include <apr_file_io.h>
#include <apr_strings.h>
#include <apr_time.h>
#include <log4cxx/helpers/pool.h>
#include <fstream>

using namespace log4cxx;

LOGUNIT_CLASS(SocketServerStarter)
{
	LOGUNIT_TEST_SUITE(SocketServerStarter);
	LOGUNIT_TEST(startServer);
	LOGUNIT_TEST_SUITE_END();

public:
	void setUp()
	{
	}

	void tearDown()
	{
	}

	void startServer()
	{
		helpers::Pool p;
		apr_pool_t* pool = p.getAPRPool();
		char* cmd = NULL;
		apr_status_t stat = apr_env_get(&cmd, "SOCKET_SERVER_COMMAND", pool);
		char* param_file = NULL;
		stat = apr_env_get(&param_file, "SOCKET_SERVER_PARAMETER_FILE", pool);

		// prepare to launch the server
		//
		apr_proc_t server_pid;
		apr_procattr_t* attr = NULL;
		stat = apr_procattr_create(&attr, pool);

		if (stat != APR_SUCCESS)
		{
			LOGUNIT_FAIL("apr_procattr_create failed");
		}

		stat = apr_procattr_io_set(attr, APR_NO_PIPE, APR_NO_PIPE, APR_NO_PIPE);

		if (stat != APR_SUCCESS)
		{
			LOGUNIT_FAIL("apr_procattr_io_set failed");
		}

		//fprintf(stdout, "SOCKET_SERVER_COMMAND=%s\n", cmd);
		stat = apr_procattr_cmdtype_set(attr, APR_PROGRAM);

		if (stat != APR_SUCCESS)
		{
			LOGUNIT_FAIL("apr_procattr_cmdtype_set failed");
		}

		if (!(cmd && *cmd) && !(param_file && *param_file))
		{
			fputs("Either:\n", stderr);
			fputs(" The environment variable SOCKET_SERVER_COMMAND"
				" must contain the server process path"
				" followed by space separated command arguments\n", stderr);
			fputs("Or:\n", stderr);
			fputs(" The file named in the environment variable SOCKET_SERVER_PARAMETER_FILE"
				" must contain a line per argument starting with the server process path"
				" followed by lines containing command arguments\n", stderr);
			LOGUNIT_FAIL("Neither SOCKET_SERVER_COMMAND nor SOCKET_SERVER_PARAMETER_FILE available.");
		}

		if (cmd && *cmd)
		{
			// convert the space separated cmd string to the argument list
			//
			static const int MaxArgumentCount = 14;
			char** argv = (char**)apr_palloc(pool, (MaxArgumentCount + 1) * sizeof(*argv));
			char* pcmd = apr_pstrdup(pool, cmd);
			int i = 0;

			for (; i < MaxArgumentCount && pcmd && *pcmd; ++i)
			{
				char separ = ' ';

				while (separ == *pcmd)
				{
					*pcmd = 0;
					++pcmd;
				}

				if ('"' == *pcmd || '\'' == *pcmd)
				{
					separ = *pcmd;
					++pcmd;
				}

				argv[i] = pcmd;

				if (NULL != (pcmd = strchr(pcmd, separ)))
				{
					*pcmd = 0;
					++pcmd;

					while (' ' == *pcmd)
					{
						*pcmd = 0;
						++pcmd;
					}
				}
			}

			argv[i] = 0;
			stat = apr_proc_create(&server_pid, argv[0], argv, NULL, attr, pool);

			if (stat == APR_SUCCESS) // Allow server time to load
			{
				apr_sleep(1000000);    // 1 seconds
			}
			else
			{
				fprintf(stderr, "apr_proc_create failed to start %s\n", argv[0]);
			}
		}

		if (param_file && *param_file)
		{
			// Build the argument list from param_file
			//
			//fprintf(stderr, "Processing: %s\n", param_file);
			std::ifstream in(param_file);
			std::vector<std::string> params;

			while (in)
			{
				params.push_back(std::string());
				std::string& line = params.back();
				std::getline(in, line);

				while (!line.empty() && (' ' == line[0] || '\t' == line[0]))
				{
					line.erase(0, 1);
				}

				while (!line.empty() && (' ' == line[line.size() - 1] || '\t' == line[line.size() - 1]))
				{
					line.erase(line.size() - 1, 1);
				}

				if (line.empty())
				{
					params.pop_back();
				}
			}

			const char** argv = (const char**)apr_palloc(pool, (params.size() + 1) * sizeof(*argv));
			int i = 0;

			for (; i < params.size(); ++i)
			{
				argv[i] = params[i].c_str();
				//fprintf(stderr, "argv[%i]: %s\n", i, argv[i]);
			}

			argv[i] = 0;
			stat = apr_proc_create(&server_pid, argv[0], argv, NULL, attr, pool);

			if (stat == APR_SUCCESS) // Allow server time to load
			{
				apr_sleep(1000000);    // 1 seconds
			}
			else
			{
				fprintf(stderr, "apr_proc_create failed to start %s\n", argv[0]);
			}
		}

		LOGUNIT_ASSERT(stat == APR_SUCCESS);
	}
};


LOGUNIT_TEST_SUITE_REGISTRATION(SocketServerStarter)

