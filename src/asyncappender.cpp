/*
 * Copyright 2003-2005 The Apache Software Foundation.
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

#include <log4cxx/asyncappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/spi/loggingevent.h>
#include <apr_thread_proc.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>
#include <log4cxx/helpers/condition.h>
#include <log4cxx/helpers/synchronized.h>
#include <apr_atomic.h>


using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

#if APR_HAS_THREADS


IMPLEMENT_LOG4CXX_OBJECT(AsyncAppender)


AsyncAppender::AsyncAppender()
: AppenderSkeleton(),
  pool(),
  queue(),
  size(DEFAULT_BUFFER_SIZE),
  available(pool),
  pending(pool),
  thread(),
  locationInfo(true),
  aai(new AppenderAttachableImpl()) {
  thread.run(dispatch, this);
}

AsyncAppender::~AsyncAppender()
{
        finalize();
}

void AsyncAppender::addAppender(const AppenderPtr& newAppender)
{
        synchronized sync(aai->getMutex());
        aai->addAppender(newAppender);
}

void AsyncAppender::append(const spi::LoggingEventPtr& event, Pool& p)
{
        // Set the NDC and thread name for the calling thread as these
        // LoggingEvent fields were not set at event creation time.
        event->getNDC();
        // Get a copy of this thread's MDC.
        event->getMDCCopy();


        //
        //   will block if queue is full
        //
        size_t count = 0;
        bool full = false;
        {
                synchronized sync(mutex);
                count = queue.size();
                full = count >= size;
                if (!full) {
                        queue.push_back(event);
                }
        }

        //
        //   if the queue had been empty then
        //      notify that there are messages pending
        if (count == 0) {
                pending.broadcast();
        }

        //
        //   if queue was full, wait until signalled
        //
        if (full) {
                available.wait();
        }

        //
        //   if was full, add it now
        //
        if (full) {
                synchronized sync(mutex);
                queue.push_back(event);
                pending.broadcast();
        }
}

void AsyncAppender::close()
{
        apr_uint32_t wasClosed = apr_atomic_xchg32(&closed, 1);
        if (!wasClosed) {
                pending.broadcast();
                thread.join();
                // close and remove all appenders
                synchronized sync(mutex);
                aai->removeAllAppenders();

        }
}

AppenderList AsyncAppender::getAllAppenders() const
{
        synchronized sync(aai->getMutex());
        return aai->getAllAppenders();
}

AppenderPtr AsyncAppender::getAppender(const LogString& name1) const
{
        synchronized sync(aai->getMutex());
        return aai->getAppender(name1);
}

bool AsyncAppender::isAttached(const AppenderPtr& appender) const
{
        synchronized sync(aai->getMutex());
        return aai->isAttached(appender);
}

void AsyncAppender::setBufferSize(int size1)
{
    if (size1 < 0) {
          throw IllegalArgumentException("size argument must be non-negative");
    }
    this->size = size1;
}

int AsyncAppender::getBufferSize() const
{
        return size;
}

void AsyncAppender::removeAllAppenders()
{
    synchronized sync(aai->getMutex());
        aai->removeAllAppenders();
}

void AsyncAppender::removeAppender(const AppenderPtr& appender)
{
    synchronized sync(aai->getMutex());
        aai->removeAppender(appender);
}

void AsyncAppender::removeAppender(const LogString& name)
{
    synchronized sync(aai->getMutex());
        aai->removeAppender(name);
}

void* LOG4CXX_THREAD_FUNC AsyncAppender::dispatch(log4cxx_thread_t* thread, void* data) {
        AsyncAppender* pThis = (AsyncAppender*) data;
        LoggingEventPtr event;
        while(true) {

                size_t count = 0;
                {
                        synchronized sync(pThis->mutex);
                        count = pThis->queue.size();
                        if (count > 0) {
                                event = pThis->queue.front();
                                pThis->queue.pop_front();
                        }
                }

                if (count == 0) {
                        if (pThis->closed) {
                                return 0;
                        }
                        pThis->pending.wait();
                } else {
                        if(pThis->aai != 0) {
                            synchronized sync(pThis->aai->getMutex());
                                Pool p;
                            pThis->aai->appendLoopOnAppenders(event, p);
                        }

                        if (count == (size_t) pThis->getBufferSize()) {
                                pThis->available.broadcast();
                        }

                        LoggingEventPtr nullEvent;
                        event = nullEvent;
                }
        }
}

#endif


