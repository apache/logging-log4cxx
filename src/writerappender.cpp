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

#include <log4cxx/writerappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/synchronized.h>
#include <log4cxx/helpers/transcoder.h>

//
//  temporary hack until build is fixed to always have apr_iconv
#define HAS_APR_ICONV 0
#if HAS_APR_ICONV
#include <apr_iconv.h>
#endif

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(WriterAppender)

WriterAppender::WriterAppender()
: immediateFlush(true), transcoder(NULL)
{
}

WriterAppender::WriterAppender(const LayoutPtr& layout)
: AppenderSkeleton(layout), immediateFlush(true), transcoder(NULL)
{
}

WriterAppender::~WriterAppender()
{
#if HAS_APR_ICONV
  if (transcoder != NULL) {
    apr_iconv_close(transcoder, pool);
  }
#endif
}

void WriterAppender::activateOptions(Pool& p) {
  AppenderSkeleton::activateOptions(p);
#if HAS_APR_ICONV
  if (transcoder != NULL) {
    apr_iconv_close(transcoder, pool);
    transcoder = NULL;
  }
  if (encoding.length() > 0) {
#if defined(LOG4CXX_LOGCHAR_IS_WCHAR)
       std::string enc;
       Transcoder::encode(encoding, enc);
       apr_status_t rv = apr_iconv_open(enc.c_str(), "WCHAR", pool, &transcoder);
       if (rv != APR_SUCCESS) {
//         LogLog::error(((LogString) LOG4CXX_STR("Unrecognized encoding "))
//             + encoding + LOG4CXX(" for appender [") + name + LOG4CXX_STR("]."));
       }
#elif defined(LOG4CXX_LOGCHAR_IS_CHAR)
#error not implemented
#else
#error either LOG4CXX_LOGCHAR_IS_WCHAR or LOG4CXX_LOGCHAR_IS_CHAR should be set
#endif

  }
#endif
}


void WriterAppender::append(const spi::LoggingEventPtr& event, Pool& pool)
{

// Reminder: the nesting of calls is:
//
//    doAppend()
//      - check threshold


//      - filter
//      - append();
//        - checkEntryConditions();

//        - subAppend();

        if(!checkEntryConditions())
        {
                return;
        }

        subAppend(event, pool);
}

bool WriterAppender::checkEntryConditions() const
{
        if(closed)
        {
                LogLog::warn(LOG4CXX_STR("Not allowed to write to a closed appender."));
                return false;
        }

        if(layout == 0)
        {
                errorHandler->error(
                        ((LogString) LOG4CXX_STR("No layout set for the appender named ["))
                        + name+ LOG4CXX_STR("]."));
                return false;
        }

        return true;
}

void WriterAppender::close()
{
        synchronized sync(mutex);

        if(closed)
        {
                return;
        }

        closed = true;
        writeFooter(pool);
        reset();
}

void WriterAppender::subAppend(const spi::LoggingEventPtr& event, Pool& p)
{
        LogString msg;
        layout->format(msg, event, p);
        subAppend(msg, pool);
}

void WriterAppender::subAppend(const LogString& msg, Pool& p) {

        if (transcoder == NULL) {
          //
          //   write to platform default MBCS
          //
          std::string encoded;
          Transcoder::encode(msg, encoded);
          subAppend(encoded.data(), encoded.length(), p);
#if HAS_APR_ICONV
        } else {
          char buf[BUFSIZE];
          char* out = buf;
          apr_size_t outbytesleft = BUFSIZE;
          const char* in = (char*) msg.data();
          apr_size_t inbytesleft = msg.length() * sizeof(logchar);
          while(inbytesleft > 0) {
            size_t converted;
            apr_status_t rv = apr_iconv(transcoder, &in, &inbytesleft,
               &out, &outbytesleft, &converted);
            if (converted > 0) {
              subAppend(buf, converted, p);
            }
            //
            //   if we fail after resetting the output buffer
            //      then output a substition character and move on
            if (rv != APR_SUCCESS && outbytesleft == BUFSIZE) {
              logchar subchar = SUBSTITUTION_CHAR;
              const char* subin = (const char*) &subchar;
              size_t subbytesleft = sizeof(logchar);
              rv = apr_iconv(transcoder, &subin, &subbytesleft,
                 &out, &outbytesleft, &converted);
              in += sizeof(logchar);
              inbytesleft -= sizeof(logchar);
              rv = apr_iconv(transcoder, &in, &inbytesleft,
                 &out, &outbytesleft, &converted);
              subAppend(buf, (out - buf), p);
            }
          }
#endif
        }
}

void WriterAppender::subAppend(const char* encoded, size_t bytes, Pool& p) {
}

void WriterAppender::reset()
{
#if HAS_APR_ICONV
       if (transcoder != NULL) {
          apr_iconv_close(transcoder, pool);
          transcoder = NULL;
       }
#endif
        closeWriter();
}

void WriterAppender::writeFooter(Pool& p)
{
        if (layout != NULL) {
          LogString foot;
          layout->appendFooter(foot, p);
          subAppend(foot, p);
        }
}

void WriterAppender::writeHeader(Pool& p)
{
        if(layout != NULL) {
          LogString header;
          layout->appendHeader(header, p);
          subAppend(header, p);
        }
}
