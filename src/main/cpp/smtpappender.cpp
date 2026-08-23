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
#include <log4cxx/net/smtpappender.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/private/string_c11.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/stringtokenizer.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/loader.h>
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/private/log4cxx_private.h>
#include <log4cxx/private/appenderskeleton_priv.h>


#include <apr_strings.h>
#include <vector>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::net;
using namespace LOG4CXX_NS::spi;

#if LOG4CXX_HAVE_LIBESMTP
	#include <auth-client.h>
	#include <libesmtp.h>
#endif

namespace
{
// RFC 5322 §2.1 defines header fields as CRLF-terminated lines, so an embedded
// CR or LF in a configured Subject/From/To/Cc/Bcc value would split it across
// header boundaries on the wire — a caller who controls a configured field
// (e.g. through ${...} property substitution from an environment variable)
// could inject arbitrary additional headers such as Bcc. The library already
// owns SMTP wire-format sanitization (see SMTPSession::toAscii, which silently
// rewrites non-ASCII to '?'); strip CR/LF in the public setters so the same
// boundary is enforced regardless of how the value reaches the appender.
LogString stripSmtpControl(const LogString& value, const logchar* field)
{
	if (value.find_first_of(LOG4CXX_STR("\r\n")) == LogString::npos)
	{
		return value;
	}
	LogString warning(LOG4CXX_STR("SMTPAppender "));
	warning.append(field);
	warning.append(LOG4CXX_STR(" contains CR or LF; stripping to prevent SMTP header injection."));
	LogLog::warn(warning);
	LogString out;
	out.reserve(value.size());
	for (auto ch : value)
	{
		if (ch != 0x0D && ch != 0x0A)
		{
			out.append(1, ch);
		}
	}
	return out;
}

} // namespace

namespace LOG4CXX_NS
{
namespace net
{
//
//   The following two classes implement an C++ SMTP wrapper over libesmtp.
//   The same signatures could be implemented over different SMTP implementations
//   or libesmtp could be combined with libgmime to enable support for non-ASCII
//   content.

#if LOG4CXX_HAVE_LIBESMTP
/**
 *   SMTP Session.
 */
class SMTPSession
{
	public:
		/**
		*   Create new instance.
		*/
		SMTPSession(const LogString& smtpHost,
			int smtpPort,
			const LogString& smtpUsername,
			const LogString& smtpPassword,
			bool allowPlainTextAuth,
			Pool& p
			)
			: user{toAscii(smtpUsername, p)}
			, pwd{toAscii(smtpPassword, p)}
		{
			auth_client_init();
			session = smtp_create_session();
			if (session == 0)
			{
				throw Exception("Could not initialize session.");
			}

			std::string host(toAscii(smtpHost, p));
			host.append(1, ':');
			host.append(p.itoa(smtpPort));
			smtp_set_server(session, host.c_str());
			smtp_set_monitorcb(session, monitor_cb, (void*)this, 1);
			smtp_set_eventcb(session, event_cb, (void*)this);

			authctx = auth_create_context();
			auth_set_mechanism_flags(authctx, AUTH_PLUGIN_PLAIN, 0);
			auth_set_interact_cb(authctx, authinteract, (void*) this);

			if (*user || *pwd)
			{
				// Secure by default: never send AUTH credentials over an
				// unencrypted connection. Require STARTTLS before
				// authenticating unless the operator explicitly opted in
				// to plain-text authentication via the
				// AllowPlainTextAuthentication option.
				if (!allowPlainTextAuth && !smtp_starttls_enable(session, Starttls_REQUIRED))
				{
					// The destructor does not run when a constructor throws
					smtp_destroy_session(session);
					auth_destroy_context(authctx);
					throw Exception("SMTPAppender: STARTTLS is unavailable in this libESMTP build;"
						" refusing to send SMTP credentials in clear text."
						" Set AllowPlainTextAuthentication=true to override.");
				}
				smtp_auth_set_context(session, authctx);
			}
		}

		~SMTPSession()
		{
			smtp_destroy_session(session);
			auth_destroy_context(authctx);
		}

		void send()
		{
			int status = smtp_start_session(session);

			if (!status)
			{
				static const size_t smtp_msgSize = 128;
				char smtp_msg[smtp_msgSize];
				smtp_strerror(smtp_errno(), smtp_msg, smtp_msgSize);
				char msg[2 * smtp_msgSize];
				snprintf(msg, sizeof (msg), "%s (sessionState %d isActive? %d tlsStarted? %d)"
					, smtp_msg, sessionState, isActive, tlsStarted);
				throw Exception(msg);
			}
			else if (incorrectAuthentication)
				throw Exception("Incorrect authentication data");
			else if (relayDenied)
				throw Exception("Relay Denied");
			else if (!certificateProblem.empty())
				throw Exception(("X509 error: " + certificateProblem).c_str());
		}

		operator smtp_session_t()
		{
			return session;
		}

		static char* toAscii(const LogString& str, Pool& p)
		{
			char* buf = p.pstralloc(str.length() + 1);
			char* current = buf;

			for (unsigned int c : str)
			{
				if (c > 0x7F)
				{
					c = '?';
				}

				*current++ = c;
			}

			*current = 0;
			return buf;
		}

	private:
		SMTPSession(SMTPSession&);
		SMTPSession& operator=(SMTPSession&);
		smtp_session_t session{0};
		auth_context_t authctx{0};
		char* user;
		char* pwd;
		int sessionState{0};
		bool isActive{false};
		bool tlsStarted{false};
		bool incorrectAuthentication{false};
		bool relayDenied{false};
		std::string certificateProblem;

		/**
		 *   This method is called if the SMTP server requests authentication.
		 */
		static int authinteract(auth_client_request_t request, char** result, int fields,
			void* arg)
		{
			auto pThis = static_cast<SMTPSession*>(arg);

			for (int i = 0; i < fields; i++)
			{
				int flag = request[i].flags & 0x07;

				if (flag == AUTH_USER)
				{
					result[i] = pThis->user;
				}
				else if (flag == AUTH_PASS)
				{
					result[i] = pThis->pwd;
				}
			}

			return 1;
		}

		static void monitor_cb(const char *buf, int buflen, int writing, void *arg)
		{
			auto pThis = static_cast<SMTPSession*>(arg);
			if (writing)
				pThis->isActive = true;
			else if (auto smtp_response = atoi(buf))
			{
				if (535 == smtp_response)
					pThis->incorrectAuthentication = true;
				if (550 == smtp_response)
					pThis->relayDenied = true;
			}

			if (LogLog::isDebugEnabled())
			{
				while (0 < buflen && std::isspace(buf[buflen - 1]))
					--buflen;
				std::string data(buf, buflen);
				LOG4CXX_DECODE_CHAR(lsData, data);
				LogString type = writing ? LOG4CXX_STR("send") : LOG4CXX_STR("recv");
				LogLog::debug(LOG4CXX_STR("SMTP ") + type + LOG4CXX_STR(" [") + lsData + LOG4CXX_STR("]"));
			}
		}

		static void event_cb (smtp_session_t session /* unused */, int event_no, void *arg,...)
		{
			auto pThis = static_cast<SMTPSession*>(arg);
			va_list alist;
			va_start(alist, arg);
			switch (event_no)
			{
			case SMTP_EV_CONNECT:
			case SMTP_EV_MAILSTATUS:
			case SMTP_EV_RCPTSTATUS:
			case SMTP_EV_MESSAGEDATA:
			case SMTP_EV_MESSAGESENT:
			case SMTP_EV_DISCONNECT:
				pThis->sessionState = event_no;
				break;
			case SMTP_EV_WEAK_CIPHER:
			{
				auto bitsRequired = va_arg(alist, long);
				pThis->certificateProblem = "weak cipher";
				if (auto ok = va_arg(alist, int*))
					*ok = 1; // Accept the problem
				break;
			}
			case SMTP_EV_STARTTLS_OK:
				pThis->tlsStarted = true;
				break;
			case SMTP_EV_INVALID_PEER_CERTIFICATE:
				pThis->certificateProblem = get_X509_error(va_arg(alist, long));
				if (auto ok = va_arg(alist, int*))
					*ok = 1; // Accept the problem
				break;
			case SMTP_EV_NO_PEER_CERTIFICATE:
				pThis->certificateProblem = "no peer certificate";
				if (auto ok = va_arg(alist, int*))
					*ok = 1;
				break;
			case SMTP_EV_WRONG_PEER_CERTIFICATE:
				pThis->certificateProblem = "wrong peer certificate";
				if (auto ok = va_arg(alist, int*))
					*ok = 1; // Accept the problem
				break;
			case SMTP_EV_NO_CLIENT_CERTIFICATE:
				pThis->certificateProblem = "no client certificate";
				if (auto ok = va_arg(alist, int*))
					*ok = 1; // Accept the problem
				break;
			}
			va_end(alist);
		}

		static std::string get_X509_error(long verifyResult)
		{
			switch (verifyResult)
			{
			case 2: return "unable to get issuer cert";
			case 3: return "unable to get crl";
			case 4: return "unable to decrypt cert signature";
			case 5: return "unable to decrypt crl signature";
			case 6: return "unable to decode issuer public key";
			case 7: return "cert signature failure";
			case 8: return "crl signature failure";
			case 9: return "cert not yet valid";
			case 10: return "cert has expired";
			case 11: return "crl not yet valid";
			case 12: return "crl has expired";
			case 13: return "error in cert not before field";
			case 14: return "error in cert not after field";
			case 15: return "error in crl last update field";
			case 16: return "error in crl next update field";
			case 17: return "out of mem";
			case 18: return "depth zero self signed cert";
			case 19: return "self signed cert in chain";
			case 20: return "unable to get issuer cert locally";
			case 21: return "unable to verify leaf signature";
			case 22: return "cert chain too long";
			case 23: return "cert revoked";
			case 24: return "invalid ca";
			case 25: return "path length exceeded";
			case 26: return "invalid purpose";
			case 27: return "cert untrusted";
			case 28: return "cert rejected";
			case 29: return "subject issuer mismatch";
			case 30: return "akid skid mismatch";
			case 31: return "akid issuer serial mismatch";
			case 32: return "keyusage no certsign";
			case 33: return "unable to get crl issuer";
			case 34: return "unhandled critical extension";
			case 35: return "keyusage no crl sign";
			case 36: return "unhandled critical crl extension";
			case 37: return "invalid non ca";
			case 38: return "proxy path length exceeded";
			case 39: return "keyusage no digital signature";
			case 40: return "proxy certificates not allowed";
			case 41: return "invalid extension";
			case 42: return "invalid policy extension";
			case 43: return "no explicit policy";
			case 44: return "different crl scope";
			case 45: return "unsupported extension feature";
			case 46: return "unnested resource";
			case 47: return "permitted violation";
			case 48: return "excluded violation";
			case 49: return "subtree minmax";
			case 51: return "unsupported constraint type";
			case 52: return "unsupported constraint syntax";
			case 53: return "unsupported name syntax";
			case 54: return "crl path validation error";
			case 50: return "application verification";
			}
			return "unknown";
		}
};

/**
 *  A message in an SMTP session.
 */
class SMTPMessage
{
	public:
		SMTPMessage(SMTPSession& session,
			const LogString& from,
			const LogString& to,
			const LogString& cc,
			const LogString& bcc,
			const LogString& subject,
			const LogString msg, Pool& p)
		{
			message = smtp_add_message(session);
			body = current = toMessage(msg, p, current_len);
			messagecbState = 0;
			smtp_set_reverse_path(message, toAscii(from, p));
			addRecipients(to, "To", p);
			addRecipients(cc, "Cc", p);
			addRecipients(bcc, "Bcc", p);

			if (!subject.empty())
			{
				smtp_set_header(message, "Subject", toAscii(subject, p));
			}

			smtp_set_messagecb(message, messagecb, this);
		}
		~SMTPMessage()
		{
		}

	private:
		SMTPMessage(const SMTPMessage&);
		SMTPMessage& operator=(const SMTPMessage&);
		smtp_message_t message;
		const char* body;
		const char* current;
		size_t current_len;
		int messagecbState;
		void addRecipients(const LogString& addresses, const char* field, Pool& p)
		{
			if (!addresses.empty())
			{
				char* str = p.pstrdup(toAscii(addresses, p));;
				smtp_set_header(message, field, NULL, str);
				char* last;

				for (char* next = apr_strtok(str, ",", &last);
					next;
					next = apr_strtok(NULL, ",", &last))
				{
					smtp_add_recipient(message, next);
				}
			}
		}
		static const char* toAscii(const LogString& str, Pool& p)
		{
			return SMTPSession::toAscii(str, p);
		}

		/**
		 *   Message bodies can only contain US-ASCII characters and
		 *   CR and LFs can only occur together.
		 *   On return \c lenOut holds the length of the converted body.
		 */
		static const char* toMessage(const LogString& str, Pool& p, size_t& lenOut)
		{
			//
			//    count the number of carriage returns and line feeds
			//
			int feedCount = 0;

			for (size_t pos = str.find_first_of(LOG4CXX_STR("\n\r"));
				pos != LogString::npos;
				pos = str.find_first_of(LOG4CXX_STR("\n\r"), ++pos))
			{
				feedCount++;
			}

			//
			//   allocate sufficient space for the modified message
			char* retval = p.pstralloc(str.length() + feedCount + 1);
			char* current = retval;
			char* startOfLine = current;
			unsigned int ignoreChar = 0;

			//
			//    iterator through message
			//
			for (unsigned int c : str)
			{
				//
				//   replace non-ASCII characters and embedded NULs with '?'
				//   (a NUL octet must never act as a body terminator)
				//
				if (c > 0x7F || c == 0)
				{
					*current++ = 0x3F; // '?'
				}
				else if (c == 0x0A || c == 0x0D)
				{
					//
					//   replace any stray CR or LF with CRLF
					//      reset start of line
					if (c == ignoreChar && current == startOfLine)
						ignoreChar = 0;
					else
					{
						*current++ = 0x0D;
						*current++ = 0x0A;
						startOfLine = current;
						ignoreChar = (c == 0x0A ? 0x0D : 0x0A);
					}
				}
				else
				{
					//
					//    truncate any lines to 1000 characters (including CRLF)
					//       as required by RFC.
					if (current < startOfLine + 998)
					{
						*current++ = (char) c;
					}
				}
			}

			*current = 0;
			lenOut = current - retval;
			return retval;
		}

		/**
		 *  Callback for message.
		 */
		static const char* messagecb(void** ctx, int* len, void* arg)
		{
			*ctx = 0;
			const char* retval = 0;
			SMTPMessage* pThis = (SMTPMessage*) arg;

			//   rewind message
			if (len == NULL)
			{
				pThis->current = pThis->body;
			}
			else
			{
				// we are asked for headers, but we don't have any
				if ((pThis->messagecbState)++ == 0)
				{
					return NULL;
				}

				if (pThis->current)
				{
					// Use the stored post-conversion length: strnlen_s over the
					// pre-conversion length truncates at an embedded NUL and
					// undercounts the CRLF-expanded body, silently dropping the
					// newest content from the alert email.
					*len = static_cast<int>(pThis->current_len);
				}

				retval = pThis->current;
				pThis->current = 0;
			}

			return retval;
		}

};
#endif

class LOG4CXX_EXPORT DefaultEvaluator
#if LOG4CXX_ABI_VERSION <= 15
	: public virtual spi::TriggeringEventEvaluator
	, public virtual helpers::Object
#else
	: public spi::TriggeringEventEvaluator
#endif
{
	public:
		DECLARE_LOG4CXX_OBJECT(DefaultEvaluator)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(DefaultEvaluator)
		LOG4CXX_CAST_ENTRY(spi::TriggeringEventEvaluator)
		END_LOG4CXX_CAST_MAP()

		DefaultEvaluator();

		/**
		Is this <code>event</code> the e-mail triggering event?
		<p>This method returns <code>true</code>, if the event level
		has ERROR level or higher. Otherwise it returns
		<code>false</code>.
		*/
		bool isTriggeringEvent(const spi::LoggingEventPtr& event) override;
	private:
		DefaultEvaluator(const DefaultEvaluator&);
		DefaultEvaluator& operator=(const DefaultEvaluator&);
}; // class DefaultEvaluator

}
}

IMPLEMENT_LOG4CXX_OBJECT(DefaultEvaluator)
IMPLEMENT_LOG4CXX_OBJECT(SMTPAppender)

struct SMTPAppender::SMTPPriv : public AppenderSkeletonPrivate
{
	SMTPPriv() :
		AppenderSkeletonPrivate(),
		smtpPort(25),
		bufferSize(512),
		locationInfo(false),
		cb(bufferSize),
		evaluator(new DefaultEvaluator()) {}

	SMTPPriv(spi::TriggeringEventEvaluatorPtr evaluator) :
		AppenderSkeletonPrivate(),
		smtpPort(25),
		bufferSize(512),
		locationInfo(false),
		cb(bufferSize),
		evaluator(evaluator) {}

	LogString to;
	LogString cc;
	LogString bcc;
	LogString from;
	LogString subject;
	LogString smtpHost;
	LogString smtpUsername;
	LogString smtpPassword;
	int smtpPort;
	int bufferSize; // 512
	bool locationInfo;
	helpers::CyclicBuffer cb;
	spi::TriggeringEventEvaluatorPtr evaluator;
	// Whether AUTH credentials may be sent without STARTTLS (see setOption)
	bool allowPlainTextAuth{false};
};

#define _priv static_cast<SMTPPriv*>(m_priv.get())

DefaultEvaluator::DefaultEvaluator()
{
}

bool DefaultEvaluator::isTriggeringEvent(const spi::LoggingEventPtr& event)
{
	return event->getLevel()->isGreaterOrEqual(Level::getError());
}

SMTPAppender::SMTPAppender()
	: AppenderSkeleton (std::make_unique<SMTPPriv>())
{
}

/**
Use <code>evaluator</code> passed as parameter as the
TriggeringEventEvaluator for this SMTPAppender.  */
SMTPAppender::SMTPAppender(spi::TriggeringEventEvaluatorPtr evaluator)
	: AppenderSkeleton (std::make_unique<SMTPPriv>(evaluator))
{
}

SMTPAppender::~SMTPAppender()
{
	_priv->setClosed();
}

bool SMTPAppender::requiresLayout() const
{
	return true;
}

LogString SMTPAppender::getFrom() const
{
	return _priv->from;
}

void SMTPAppender::setFrom(const LogString& newVal)
{
	_priv->from = stripSmtpControl(newVal, LOG4CXX_STR("From"));
}


LogString SMTPAppender::getSubject() const
{
	return _priv->subject;
}

void SMTPAppender::setSubject(const LogString& newVal)
{
	_priv->subject = stripSmtpControl(newVal, LOG4CXX_STR("Subject"));
}

LogString SMTPAppender::getSMTPHost() const
{
	return _priv->smtpHost;
}

void SMTPAppender::setSMTPHost(const LogString& newVal)
{
	_priv->smtpHost = newVal;
}

int SMTPAppender::getSMTPPort() const
{
	return _priv->smtpPort;
}

void SMTPAppender::setSMTPPort(int newVal)
{
	_priv->smtpPort = newVal;
}

bool SMTPAppender::getLocationInfo() const
{
	return _priv->locationInfo;
}

void SMTPAppender::setLocationInfo(bool newVal)
{
	_priv->locationInfo = newVal;
}

LogString SMTPAppender::getSMTPUsername() const
{
	return _priv->smtpUsername;
}

void SMTPAppender::setSMTPUsername(const LogString& newVal)
{
	_priv->smtpUsername = newVal;
}

LogString SMTPAppender::getSMTPPassword() const
{
	return _priv->smtpPassword;
}

void SMTPAppender::setSMTPPassword(const LogString& newVal)
{
	_priv->smtpPassword = newVal;
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
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("SMTPUSERNAME"), LOG4CXX_STR("smtpusername")))
	{
		setSMTPUsername(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("SMTPPASSWORD"), LOG4CXX_STR("smtppassword")))
	{
		setSMTPPassword(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("SUBJECT"), LOG4CXX_STR("subject")))
	{
		setSubject(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("TO"), LOG4CXX_STR("to")))
	{
		setTo(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("CC"), LOG4CXX_STR("cc")))
	{
		setCc(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("BCC"), LOG4CXX_STR("bcc")))
	{
		setBcc(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("SMTPPORT"), LOG4CXX_STR("smtpport")))
	{
		setSMTPPort(OptionConverter::toInt(value, 25));
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("ALLOWPLAINTEXTAUTHENTICATION"), LOG4CXX_STR("allowplaintextauthentication")))
	{
		// Explicit opt-out from the STARTTLS-before-AUTH requirement;
		// only for servers that cannot offer TLS on a trusted network.
		_priv->allowPlainTextAuth = OptionConverter::toBoolean(value, false);
	}
	else
	{
		AppenderSkeleton::setOption(option, value);
	}
}


bool SMTPAppender::asciiCheck(const LogString& value, const LogString& field)
{
	for (unsigned int item : value)
	{
		if (0x7F < item)
		{
			LogLog::warn(field + LOG4CXX_STR(" contains non-ASCII character"));
			return false;
		}
	}

	return true;
}

/**
Activate the specified options, such as the smtp host, the
recipient, from, etc. */
void SMTPAppender::activateOptions( LOG4CXX_ACTIVATE_OPTIONS_FORMAL_PARAMETERS )
{
	if (_priv->layout == 0)
	{
		_priv->errorHandler->error(LOG4CXX_STR("No layout set for appender named [") + _priv->name + LOG4CXX_STR("]."));
	}

	if (_priv->evaluator == 0)
	{
		_priv->errorHandler->error(LOG4CXX_STR("No TriggeringEventEvaluator is set for appender [") +
			_priv->name + LOG4CXX_STR("]."));
	}

	if (_priv->smtpHost.empty())
	{
		_priv->errorHandler->error(LOG4CXX_STR("No smtpHost is set for appender [") +
			_priv->name + LOG4CXX_STR("]."));
	}

	if (_priv->to.empty() && _priv->cc.empty() && _priv->bcc.empty())
	{
		_priv->errorHandler->error(LOG4CXX_STR("No recipient address is set for appender [") +
			_priv->name + LOG4CXX_STR("]."));
	}

	asciiCheck(_priv->to, LOG4CXX_STR("to"));
	asciiCheck(_priv->cc, LOG4CXX_STR("cc"));
	asciiCheck(_priv->bcc, LOG4CXX_STR("bcc"));
	asciiCheck(_priv->from, LOG4CXX_STR("from"));

#if !LOG4CXX_HAVE_LIBESMTP
	_priv->errorHandler->error(LOG4CXX_STR("log4cxx built without SMTP support."));
#endif
}

/**
Perform SMTPAppender specific appending actions, mainly adding
the event to a cyclic buffer and checking if the event triggers
an e-mail to be sent. */
void SMTPAppender::append( LOG4CXX_APPEND_FORMAL_PARAMETERS )
{
	if (!checkEntryConditions())
	{
		return;
	}

	// Get a copy of this thread's diagnostic context
	event->LoadDC();

	_priv->cb.add(event);

	if (_priv->evaluator->isTriggeringEvent(event))
	{
		Pool p;
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
#if LOG4CXX_HAVE_LIBESMTP

	if ((_priv->to.empty() && _priv->cc.empty() && _priv->bcc.empty()) || _priv->from.empty() || _priv->smtpHost.empty())
	{
		_priv->errorHandler->error(LOG4CXX_STR("Message not configured."));
		return false;
	}

	if (_priv->evaluator == 0)
	{
		_priv->errorHandler->error(LOG4CXX_STR("No TriggeringEventEvaluator is set for appender [") +
			_priv->name + LOG4CXX_STR("]."));
		return false;
	}


	if (_priv->layout == 0)
	{
		_priv->errorHandler->error(LOG4CXX_STR("No layout set for appender named [") + _priv->name + LOG4CXX_STR("]."));
		return false;
	}

	return true;
#else
	return false;
#endif
}



void SMTPAppender::close()
{
	_priv->setClosed();
}

LogString SMTPAppender::getTo() const
{
	return _priv->to;
}

void SMTPAppender::setTo(const LogString& addressStr)
{
	_priv->to = stripSmtpControl(addressStr, LOG4CXX_STR("To"));
}

LogString SMTPAppender::getCc() const
{
	return _priv->cc;
}

void SMTPAppender::setCc(const LogString& addressStr)
{
	_priv->cc = stripSmtpControl(addressStr, LOG4CXX_STR("Cc"));
}

LogString SMTPAppender::getBcc() const
{
	return _priv->bcc;
}

void SMTPAppender::setBcc(const LogString& addressStr)
{
	_priv->bcc = stripSmtpControl(addressStr, LOG4CXX_STR("Bcc"));
}

/**
Send the contents of the cyclic buffer as an e-mail message.
*/
void SMTPAppender::sendBuffer(Pool& p)
{
#if LOG4CXX_HAVE_LIBESMTP

	// This thread owns the mutex for this appender, hence no need to synchronize on 'cb'.
	try
	{
		LogString sbuf;
		_priv->layout->appendHeader(sbuf);

		int len = _priv->cb.length();

		for (int i = 0; i < len; i++)
		{
			LoggingEventPtr event = _priv->cb.get();
			_priv->layout->format(sbuf, event);
		}

		_priv->layout->appendFooter(sbuf);

		SMTPSession session(_priv->smtpHost, _priv->smtpPort, _priv->smtpUsername, _priv->smtpPassword, _priv->allowPlainTextAuth, p);

		SMTPMessage message(session, _priv->from, _priv->to, _priv->cc,
			_priv->bcc, _priv->subject, sbuf, p);

		session.send();

	}
	catch (std::exception& e)
	{
		_priv->errorHandler->error(LOG4CXX_STR("Error occured while sending e-mail to [") + _priv->smtpHost + LOG4CXX_STR("]."), e, 0);
	}

#endif
}

/**
Returns value of the <b>EvaluatorClass</b> option.
*/
LogString SMTPAppender::getEvaluatorClass()
{
	return _priv->evaluator == 0 ? LogString() : _priv->evaluator->getClass().getName();
}

LOG4CXX_NS::spi::TriggeringEventEvaluatorPtr SMTPAppender::getEvaluator() const
{
	return _priv->evaluator;
}

void SMTPAppender::setEvaluator(LOG4CXX_NS::spi::TriggeringEventEvaluatorPtr& trigger)
{
	_priv->evaluator = trigger;
}

/**
The <b>BufferSize</b> option takes a positive integer
representing the maximum number of logging events to collect in a
cyclic buffer. When the <code>BufferSize</code> is reached,
oldest events are deleted as new events are added to the
buffer. By default the size of the cyclic buffer is 512 events.
*/
void SMTPAppender::setBufferSize(int sz)
{
	if (sz < 1)
	{
		sz = 1;
	}

	_priv->bufferSize = sz;
	_priv->cb.resize(sz);
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
	ObjectPtr obj = ObjectPtr(Loader::loadClass(value).newInstance());
	_priv->evaluator = LOG4CXX_NS::cast<TriggeringEventEvaluator>(obj);
}

int SMTPAppender::getBufferSize() const
{
	return _priv->bufferSize;
}
