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

#include <log4cxx/private/log4cxx_private.h>
#if LOG4CXX_HAVE_SMTP

#include <log4cxx/net/smtpappender.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/stringtokenizer.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/synchronized.h>

#include <libsmtp.h>
#include <libsmtp_mime.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::net;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(DefaultEvaluator)
IMPLEMENT_LOG4CXX_OBJECT(SMTPAppender)

DefaultEvaluator::DefaultEvaluator() {
}

bool DefaultEvaluator::isTriggeringEvent(const spi::LoggingEventPtr& event)
{
   return event->getLevel()->isGreaterOrEqual(Level::getError());
}

SMTPAppender::SMTPAppender()
: bufferSize(512), locationInfo(false), cb(bufferSize),
evaluator(new DefaultEvaluator()), session(0),
encoding(LOG4CXX_STR("7bit")), charset(LOG4CXX_STR("us-ascii"))
{
}

/**
Use <code>evaluator</code> passed as parameter as the
TriggeringEventEvaluator for this SMTPAppender.  */
SMTPAppender::SMTPAppender(spi::TriggeringEventEvaluatorPtr evaluator)
: bufferSize(512), locationInfo(false), cb(bufferSize),
evaluator(evaluator), session(0),
encoding(LOG4CXX_STR("7bit")), charset(LOG4CXX_STR("us-ascii"))
{
}

SMTPAppender::~SMTPAppender()
{
   finalize();
}

void SMTPAppender::setOption(const LogString& option,
   const LogString& value)
{
   if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("BUFFERSIZE"), LOG4CXX_STR("buffersize")))
   {
      setBufferSize(OptionConverter::toInt(value, 512));
   }
   else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("EVALUATORCLASS"), LOG4CXX_STR("evaluatorclass")))
   {
      setEvaluatorClass(value);
   }
   else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("FROM"), LOG4CXX_STR("from")))
   {
      setFrom(value);
   }
   else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("SMTPHOST"), LOG4CXX_STR("smtphost")))
   {
      setSMTPHost(value);
   }
   else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("SUBJECT"), LOG4CXX_STR("subject")))
   {
      setSubject(value);
   }
   else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("TO"), LOG4CXX_STR("to")))
   {
      setTo(value);
   }
   else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("CHARSET"), LOG4CXX_STR("charset")))
   {
      setCharset(value);
   }
   else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("ENCODING"), LOG4CXX_STR("encoding")))
   {
      setEncoding(value);
   }
   else
   {
      AppenderSkeleton::setOption(option, value);
   }
}

/**
Activate the specified options, such as the smtp host, the
recipient, from, etc. */
void SMTPAppender::activateOptions(Pool& p)
{
   session = ::libsmtp_session_initialize();
   if (session == 0)
   {
      LogLog::error(LOG4CXX_STR("Could not intialize session."));
      return;
   }

   LOG4CXX_ENCODE_CHAR(ansiFrom, from);
   LOG4CXX_ENCODE_CHAR(ansiSubject, subject);
   ::libsmtp_set_environment(
      const_cast<char*>(ansiFrom.c_str()),
      const_cast<char*>(ansiSubject.c_str()),
      0,
      (libsmtp_session_struct *)session);

   std::vector<LogString> recipients = parseAddress(to);
   std::vector<LogString>::iterator i;
   for (i = recipients.begin(); i != recipients.end(); i++)
   {
      LOG4CXX_ENCODE_CHAR(ansiTo, *i);
      if (::libsmtp_add_recipient(LIBSMTP_REC_TO,
         const_cast<char*>(ansiTo.c_str()),
         (libsmtp_session_struct *)session) != 0)
      {
         LogLog::error(LOG4CXX_STR("Could not add recipient ")+ *i + LOG4CXX_STR("."));
         return;
      }
   }

   // MIMEPART
   if (layout != 0)
   {
      int mimeType = 0;
      LogString contentType(layout->getContentType());
      if (contentType == LOG4CXX_STR("text/plain"))
      {
         mimeType = LIBSMTP_MIME_SUB_PLAIN;
      }
      else if (contentType == LOG4CXX_STR("text/html"))
      {
         mimeType = LIBSMTP_MIME_SUB_HTML;
      }
      else
      {
         LogLog::error(LOG4CXX_STR("invalid layout content type: ")+contentType+LOG4CXX_STR("."));
         return;
      }

      int charset = 0;
      if (this->charset == LOG4CXX_STR("us-ascii"))
      {
          charset = LIBSMTP_CHARSET_USASCII;
      }
      else if (this->charset == LOG4CXX_STR("iso8859_1"))
      {
          charset = LIBSMTP_CHARSET_ISO8859_1;
      }
      else if (this->charset == LOG4CXX_STR("iso8859_2"))
      {
          charset = LIBSMTP_CHARSET_ISO8859_2;
      }
      else if (this->charset == LOG4CXX_STR("iso8859_3"))
      {
          charset = LIBSMTP_CHARSET_ISO8859_3;
      }
      else
      {
         LogLog::error(LOG4CXX_STR("invalid charset: ")+this->charset+LOG4CXX_STR("."));
         return;
      }

      int encoding = 0;
      if (this->encoding == LOG4CXX_STR("7bit"))
      {
         encoding = LIBSMTP_ENC_7BIT;
      }
      else if (this->encoding == LOG4CXX_STR("8bit"))
      {
         encoding = LIBSMTP_ENC_8BIT;
      }
      else if (this->encoding == LOG4CXX_STR("binary"))
      {
         encoding = LIBSMTP_ENC_BINARY;
      }
      else if (this->encoding == LOG4CXX_STR("base64"))
      {
         encoding = LIBSMTP_ENC_BASE64;
      }
      else if (this->encoding == LOG4CXX_STR("quoted"))
      {
         encoding = LIBSMTP_ENC_QUOTED;
      }
      else
      {
         LogLog::error(LOG4CXX_STR("invalid encoding: ")+this->encoding+LOG4CXX_STR("."));
         return;
      }

      libsmtp_part_struct * part = 0;
      part = ::libsmtp_part_new(
         0,
         LIBSMTP_MIME_TEXT,
         mimeType,
         encoding,
         charset,
         "content",
         (libsmtp_session_struct *)session);
      if (part == 0)
      {
         LogLog::error(LOG4CXX_STR("Error adding part."));
      }
   }
   else
   {
      LogLog::error(LOG4CXX_STR("Layout not set !"));
   }
}

/**
Perform SMTPAppender specific appending actions, mainly adding
the event to a cyclic buffer and checking if the event triggers
an e-mail to be sent. */
void SMTPAppender::append(const spi::LoggingEventPtr& event, Pool& p)
{
   if(!checkEntryConditions())
   {
      return;
   }

   event->getNDC();

/* if(locationInfo)
   {
      event.getLocationInformation();
   }*/

   cb.add(event);

   if(evaluator->isTriggeringEvent(event))
   {
      sendBuffer(p);
   }
}

/**
This method determines if there is a sense in attempting to append.
<p>It checks whether there is a set output target and also if
there is a set layout. If these checks fail, then the boolean
value <code>false</code> is returned. */
bool SMTPAppender::checkEntryConditions()
{
   if(to.empty() || from.empty() || subject.empty() || smtpHost.empty())
   {
      errorHandler->error(LOG4CXX_STR("Message not configured."));
      return false;
   }

   if(evaluator == 0)
   {
      errorHandler->error(LOG4CXX_STR("No TriggeringEventEvaluator is set for appender [")+
         name+ LOG4CXX_STR("]."));
      return false;
   }


   if(layout == 0)
   {
      errorHandler->error(LOG4CXX_STR("No layout set for appender named [")+name+LOG4CXX_STR("]."));
      return false;
   }
   return true;
}

void SMTPAppender::close()
{
   synchronized sync(this);
   if (!this->closed && session != 0)
   {
      ::libsmtp_free((libsmtp_session_struct *)session);
      session = 0;
   }

   this->closed = true;
}

std::vector<LogString> SMTPAppender::parseAddress(const LogString& addressStr)
{
   std::vector<LogString> addresses;

   StringTokenizer st(addressStr, LOG4CXX_STR(","));
   while (st.hasMoreTokens())
   {
      addresses.push_back(st.nextToken());
   }

   return addresses;
}

/**
Send the contents of the cyclic buffer as an e-mail message.
*/
void SMTPAppender::sendBuffer(Pool& p)
{
   // Note: this code already owns the monitor for this
   // appender. This frees us from needing to synchronize on 'cb'.
   try
   {
      LogString sbuf;
      layout->appendHeader(sbuf, p);

      int len = cb.length();
      for(int i = 0; i < len; i++)
      {
            //sbuf.append(MimeUtility.encodeText(layout.format(cb.get())));
         LoggingEventPtr event = cb.get();
         layout->format(sbuf, event, p);
      }

      layout->appendFooter(sbuf, p);

      LOG4CXX_ENCODE_CHAR(aSmtpHost, smtpHost);

      /* This starts the SMTP connection */
      if (::libsmtp_connect(
         const_cast<char*>(aSmtpHost.c_str()),
         0,
         0,
         (libsmtp_session_struct *)session) != 0)
      {
         LogLog::error(LOG4CXX_STR("Error occured while starting the SMTP connection."));
         return;
      }

      /* This will conduct the SMTP dialogue */
      if (::libsmtp_dialogue((libsmtp_session_struct *)session) != 0)
      {
         LogLog::error(LOG4CXX_STR("Error occured while conducting the SMTP dialogue."));
         return;
      }

      /* Now lets send the headers */
      if (::libsmtp_headers((libsmtp_session_struct *)session) != 0)
      {
         LogLog::error(LOG4CXX_STR("Error occured while sending the headers."));
         return;
      }

      /* Now lets send the MIME headers */
      if (::libsmtp_mime_headers((libsmtp_session_struct *)session) != 0)
      {
         LogLog::error(LOG4CXX_STR("Error occured while sending the MIME headers."));
         return;
      }

      LOG4CXX_ENCODE_CHAR(s, sbuf);
      if (::libsmtp_part_send(
         const_cast<char*>(s.c_str()),
         s.length(),
         (libsmtp_session_struct *)session) != 0)
      {
         LogLog::error(LOG4CXX_STR("Error occured while sending the message body."));
      }

      /* This ends the body part */
      if (::libsmtp_body_end((libsmtp_session_struct *)session) != 0)
      {
         LogLog::error(LOG4CXX_STR("Error occured while ending the body part."));
         return;
      }

      /* This ends the connection gracefully */
      if (::libsmtp_quit((libsmtp_session_struct *)session) != 0)
      {
         LogLog::error(LOG4CXX_STR("Error occured while ending the connection."));
         return;
      }

   }
   catch(std::exception& e)
   {
      LogLog::error(LOG4CXX_STR("Error occured while sending e-mail notification."), e);
   }
}

/**
Returns value of the <b>EvaluatorClass</b> option.
*/
LogString SMTPAppender::getEvaluatorClass()
{
   return evaluator == 0 ? LogString() : evaluator->getClass().getName();
}

/**
The <b>BufferSize</b> option takes a positive integer
representing the maximum number of logging events to collect in a
cyclic buffer. When the <code>BufferSize</code> is reached,
oldest events are deleted as new events are added to the
buffer. By default the size of the cyclic buffer is 512 events.
*/
void SMTPAppender::setBufferSize(int bufferSize)
{
   this->bufferSize = bufferSize;
   cb.resize(bufferSize);
}

/**
The <b>EvaluatorClass</b> option takes a string value
representing the name of the class implementing the {@link
TriggeringEventEvaluator} interface. A corresponding object will
be instantiated and assigned as the triggering event evaluator
for the SMTPAppender.
*/
void SMTPAppender::setEvaluatorClass(const LogString& value)
{
   evaluator = OptionConverter::instantiateByClassName(value,
      TriggeringEventEvaluator::getStaticClass(), evaluator);
}

#endif //LOG4CXX_HAVE_SMTP

