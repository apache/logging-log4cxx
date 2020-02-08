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

     if (cmd && *cmd)
     {
          // prepare to launch the server
          //
          apr_proc_t server_pid;
          apr_procattr_t* attr = NULL;
          stat = apr_procattr_create(&attr, pool);
          LOGUNIT_ASSERT(stat == APR_SUCCESS);
          stat = apr_procattr_io_set(attr, APR_NO_PIPE, APR_NO_PIPE, APR_NO_PIPE);
          LOGUNIT_ASSERT(stat == APR_SUCCESS);

          //fprintf(stdout, "SOCKET_SERVER_COMMAND=%s\n", cmd);
#ifdef SHELL_CMD_TYPE_WORKS
          stat = apr_procattr_cmdtype_set(attr, APR_SHELLCMD);
          LOGUNIT_ASSERT(stat == APR_SUCCESS);
          stat = apr_proc_create(&server_pid, cmd, NULL, NULL, attr, pool);
#else
          stat = apr_procattr_cmdtype_set(attr, APR_PROGRAM);
          LOGUNIT_ASSERT(stat == APR_SUCCESS);
          // convert the space separated cmd string to the argument list
          //
          char** args = (char**)apr_palloc(pool, 15 * sizeof(*args));
          char* pcmd = apr_pstrdup(pool, cmd);
          int i = 0;
          for (; i < 14 && pcmd && *pcmd; ++i)
          {
              args[i] = pcmd;
              if (NULL != (pcmd = strchr(pcmd, ' ')))
              {
                while(' ' == *pcmd)
                {
                  *pcmd = 0;
                  ++pcmd;
                }
              }
          }
          args[i] = 0;
          //fprintf(stdout, "starting=%s with %d arguments\n", args[0], i);
          stat = apr_proc_create(&server_pid, args[0], args, NULL, attr, pool);
#endif


          if (stat == APR_SUCCESS) // Allow server time to load
              apr_sleep(1000000); // 1 seconds
      }
      else
          fputs("The environment variable SOCKET_SERVER_COMMAND"
               " must contain the server process path"
               " followed by space separated command arguments\n", stderr);

      LOGUNIT_ASSERT(stat == APR_SUCCESS);
   }
};


LOGUNIT_TEST_SUITE_REGISTRATION(SocketServerStarter)

