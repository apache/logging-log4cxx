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
#include <log4cxx/db/odbcappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/patternlayout.h>
#include <apr_strings.h>

#include <log4cxx/pattern/loggerpatternconverter.h>
#include <log4cxx/pattern/classnamepatternconverter.h>
#include <log4cxx/pattern/datepatternconverter.h>
#include <log4cxx/pattern/filelocationpatternconverter.h>
#include <log4cxx/pattern/fulllocationpatternconverter.h>
#include <log4cxx/pattern/shortfilelocationpatternconverter.h>
#include <log4cxx/pattern/linelocationpatternconverter.h>
#include <log4cxx/pattern/messagepatternconverter.h>
#include <log4cxx/pattern/methodlocationpatternconverter.h>
#include <log4cxx/pattern/levelpatternconverter.h>
#include <log4cxx/pattern/threadpatternconverter.h>
#include <log4cxx/pattern/threadusernamepatternconverter.h>
#include <log4cxx/pattern/ndcpatternconverter.h>
#include <log4cxx/pattern/patternparser.h>

#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/private/log4cxx_private.h>
#if LOG4CXX_HAVE_ODBC
	#if defined(WIN32) || defined(_WIN32)
		#include <windows.h>
	#endif
	#include <sqlext.h>
    #if LOG4CXX_LOGCHAR_IS_WCHAR
    #define LOG4CXX_SQL_STRING_TYPE SQL_C_WCHAR
    #else
    #define LOG4CXX_SQL_STRING_TYPE SQL_CHAR
    #endif

#else
	typedef void* SQLHSTMT;
#endif
#include <log4cxx/private/odbcappender_priv.h>
#if defined(max)
	#undef max
#endif
#include <cstring>
#include <algorithm>


using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::db;
using namespace log4cxx::spi;
using namespace log4cxx::pattern;

#if LOG4CXX_HAVE_ODBC
static LogString sqlwchar_to_logstring(SQLWCHAR* wchar_str){
    std::wstring wstr;
    LogString output;
    int x = 0;
    while(wchar_str[x] != 0){
        wstr.push_back(wchar_str[x]);
        x++;
    }

    Transcoder::decode(wstr, output);

    return output;
}
#endif

SQLException::SQLException(short fHandleType,
	void* hInput, const char* prolog,
	log4cxx::helpers::Pool& p)
	: Exception(formatMessage(fHandleType, hInput, prolog, p))
{
}


SQLException::SQLException(const char* msg)
	: Exception(msg)
{
}

SQLException::SQLException(const SQLException& src)
	: Exception(src)
{
}

const char* SQLException::formatMessage(short fHandleType,
	void* hInput, const char* prolog, log4cxx::helpers::Pool& p)
{
	std::string strReturn(prolog);
	strReturn.append(" - ");
#if LOG4CXX_HAVE_ODBC
	SQLCHAR       SqlState[6];
	SQLCHAR       Msg[SQL_MAX_MESSAGE_LENGTH];
	SQLINTEGER    NativeError;
	SQLSMALLINT   i;
	SQLSMALLINT   MsgLen;
	SQLRETURN     rc2;

	// Get the status records.
	i = 1;

	while ((rc2 = SQLGetDiagRecA(fHandleType, hInput, i, SqlState, &NativeError,
					Msg, sizeof(Msg), &MsgLen)) != SQL_NO_DATA)
	{
		strReturn.append((char*) Msg);
		i++;
	}

#else
	strReturn.append("log4cxx built without ODBC support");
#endif

	return apr_pstrdup((apr_pool_t*) p.getAPRPool(), strReturn.c_str());
}


IMPLEMENT_LOG4CXX_OBJECT(ODBCAppender)

#define _priv static_cast<ODBCAppenderPriv*>(m_priv.get())

ODBCAppender::ODBCAppender()
	: AppenderSkeleton (std::make_unique<ODBCAppenderPriv>())
{
}

ODBCAppender::~ODBCAppender()
{
	finalize();
}

#define RULES_PUT(spec, cls) \
	specs.insert(PatternMap::value_type(LogString(LOG4CXX_STR(spec)), cls ::newInstance))

static PatternMap& getFormatSpecifiers()
{
	static PatternMap specs;
	if (specs.empty())
	{
		RULES_PUT("logger", LoggerPatternConverter);
		RULES_PUT("class", ClassNamePatternConverter);
		RULES_PUT("time", DatePatternConverter);
		RULES_PUT("shortfilename", ShortFileLocationPatternConverter);
		RULES_PUT("fullfilename", FileLocationPatternConverter);
		RULES_PUT("location", FullLocationPatternConverter);
		RULES_PUT("line", LineLocationPatternConverter);
		RULES_PUT("message", MessagePatternConverter);
		RULES_PUT("method", MethodLocationPatternConverter);
		RULES_PUT("level", LevelPatternConverter);
		RULES_PUT("thread", ThreadPatternConverter);
		RULES_PUT("threadname", ThreadUsernamePatternConverter);
		RULES_PUT("ndc", NDCPatternConverter);
	}
	return specs;
}

void ODBCAppender::setOption(const LogString& option, const LogString& value)
{
	if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("BUFFERSIZE"), LOG4CXX_STR("buffersize")))
	{
		setBufferSize((size_t)OptionConverter::toInt(value, 1));
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("PASSWORD"), LOG4CXX_STR("password")))
	{
		setPassword(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("SQL"), LOG4CXX_STR("sql")))
	{
		setSql(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("URL"), LOG4CXX_STR("url"))
		|| StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("DSN"), LOG4CXX_STR("dsn"))
		|| StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("CONNECTIONSTRING"), LOG4CXX_STR("connectionstring"))  )
	{
		setURL(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("USER"), LOG4CXX_STR("user")))
	{
		setUser(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("MESSAGECHARACTERCOUNT"), LOG4CXX_STR("messagecharactercount")))
	{
		_priv->max_message_character_count = (size_t)OptionConverter::toInt(value, 1000);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("FILEPATHCHARACTERCOUNT"), LOG4CXX_STR("filepathcharactercount")))
	{
		_priv->max_file_path_character_count = (size_t)OptionConverter::toInt(value, 300);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("COLUMNMAPPING"), LOG4CXX_STR("columnmapping")))
	{
        _priv->mappedName.push_back(value);
    }
	else
	{
		AppenderSkeleton::setOption(option, value);
	}
}

//* Does ODBCAppender require a layout?

bool ODBCAppender::requiresLayout() const
{
    return _priv->sqlFormatters.empty();
}

void ODBCAppender::activateOptions(log4cxx::helpers::Pool& p)
{
#if !LOG4CXX_HAVE_ODBC
	LogLog::error(LOG4CXX_STR("Can not activate ODBCAppender unless compiled with ODBC support."));
#else
	auto& specs = getFormatSpecifiers();
	for (auto& name : _priv->mappedName)
	{
		auto pItem = specs.find(StringHelper::toLowerCase(name));
		if (specs.end() == pItem)
			LogLog::error(name + LOG4CXX_STR(" is not a supported ColumnMapping value"));
		else
		{
			std::vector<LogString> options;
			if (LOG4CXX_STR("time") == pItem->first)
				options.push_back(LOG4CXX_STR("dd MMM yyyy HH:mm:ss.SSS"));
			auto converter = log4cxx::cast<LoggingEventPatternConverter>((pItem->second)(options));
			size_t max_character_count = 30;
			if (LOG4CXX_STR("message") == pItem->first)
				max_character_count = _priv->max_message_character_count;
			else if (LOG4CXX_STR("fullfilename") == pItem->first)
				max_character_count = _priv->max_file_path_character_count;
            _priv->sqlFormatters.emplace_back(converter);
		}
	}

    SQLHDBC con = getConnection(p);

    if (_priv->preparedStatement != nullptr){
        SQLFreeHandle(SQL_HANDLE_STMT, _priv->preparedStatement);
        _priv->preparedStatement = nullptr;
    }
    SQLRETURN ret = SQLAllocHandle( SQL_HANDLE_STMT, con, &_priv->preparedStatement);
    if (ret < 0)
    {
        SQLException ex(SQL_HANDLE_ENV, _priv->env, "Failed to allocate SQL prepared statement", p);
        _priv->preparedStatement = nullptr;
        throw ex;
    }

    SQLWCHAR* wsql;
    encode(&wsql, _priv->sqlStatement, p);
    ret = SQLPrepareW(_priv->preparedStatement, wsql, SQL_NTS);
    if (ret < 0)
    {
        throw SQLException(SQL_HANDLE_STMT, _priv->preparedStatement, "Failed to prepare sql statement.", p);
    }
#endif
}


void ODBCAppender::append(const spi::LoggingEventPtr& event, log4cxx::helpers::Pool& p)
{
#if LOG4CXX_HAVE_ODBC
	_priv->buffer.push_back(event);

	if (_priv->buffer.size() >= _priv->bufferSize)
	{
		flushBuffer(p);
	}

#endif
}

LogString ODBCAppender::getLogStatement(const spi::LoggingEventPtr& event, log4cxx::helpers::Pool& p) const
{
	LogString sbuf;
	getLayout()->format(sbuf, event, p);
	return sbuf;
}

void ODBCAppender::execute(const LogString& sql, log4cxx::helpers::Pool& p)
{
#if LOG4CXX_HAVE_ODBC
	SQLRETURN ret;
	SQLHDBC con = SQL_NULL_HDBC;
	SQLHSTMT stmt = SQL_NULL_HSTMT;

	try
	{
		con = getConnection(p);

		ret = SQLAllocHandle( SQL_HANDLE_STMT, con, &stmt);

		if (ret < 0)
		{
			throw SQLException( SQL_HANDLE_DBC, con, "Failed to allocate sql handle", p);
		}

		SQLWCHAR* wsql;
		encode(&wsql, sql, p);
		ret = SQLExecDirectW(stmt, wsql, SQL_NTS);

		if (ret < 0)
		{
			throw SQLException(SQL_HANDLE_STMT, stmt, "Failed to execute sql statement", p);
		}
	}
	catch (SQLException&)
	{
		if (stmt != SQL_NULL_HSTMT)
		{
			SQLFreeHandle(SQL_HANDLE_STMT, stmt);
		}

		throw;
	}

	SQLFreeHandle(SQL_HANDLE_STMT, stmt);
	closeConnection(con);
#else
	throw SQLException("log4cxx build without ODBC support");
#endif
}

/* The default behavior holds a single connection open until the appender
is closed (typically when garbage collected).*/
void ODBCAppender::closeConnection(ODBCAppender::SQLHDBC /* con */)
{
}

ODBCAppender::SQLHDBC ODBCAppender::getConnection(log4cxx::helpers::Pool& p)
{
#if LOG4CXX_HAVE_ODBC
	SQLRETURN ret;

	if (_priv->env == SQL_NULL_HENV)
	{
		ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &_priv->env);

		if (ret < 0)
		{
			SQLException ex(SQL_HANDLE_ENV, _priv->env, "Failed to allocate SQL handle", p);
			_priv->env = SQL_NULL_HENV;
			throw ex;
		}

		ret = SQLSetEnvAttr(_priv->env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER) SQL_OV_ODBC3, SQL_IS_INTEGER);

		if (ret < 0)
		{
			SQLException ex(SQL_HANDLE_ENV, _priv->env, "Failed to set odbc version", p);
			SQLFreeHandle(SQL_HANDLE_ENV, _priv->env);
			_priv->env = SQL_NULL_HENV;
			throw ex;
		}
	}

	if (_priv->connection == SQL_NULL_HDBC)
	{
		ret = SQLAllocHandle(SQL_HANDLE_DBC, _priv->env, &_priv->connection);

		if (ret < 0)
		{
			SQLException ex(SQL_HANDLE_DBC, _priv->connection, "Failed to allocate sql handle", p);
			_priv->connection = SQL_NULL_HDBC;
			throw ex;
		}


		SQLWCHAR* wURL, *wUser, *wPwd;
		encode(&wURL, _priv->databaseURL, p);
		encode(&wUser, _priv->databaseUser, p);
		encode(&wPwd, _priv->databasePassword, p);

		ret = SQLConnectW( _priv->connection,
				wURL, SQL_NTS,
				wUser, SQL_NTS,
				wPwd, SQL_NTS);


		if (ret < 0)
		{
			SQLException ex(SQL_HANDLE_DBC, _priv->connection, "Failed to connect to database", p);
			SQLFreeHandle(SQL_HANDLE_DBC, _priv->connection);
			_priv->connection = SQL_NULL_HDBC;
			throw ex;
		}
	}

	return _priv->connection;
#else
	return 0;
#endif
}

void ODBCAppender::close()
{
	if (_priv->closed)
	{
		return;
	}

	Pool p;

	try
	{
		flushBuffer(p);
	}
	catch (SQLException& e)
	{
		_priv->errorHandler->error(LOG4CXX_STR("Error closing connection"),
			e, ErrorCode::GENERIC_FAILURE);
	}

#if LOG4CXX_HAVE_ODBC

    if (_priv->preparedStatement != nullptr){
        SQLFreeHandle(SQL_HANDLE_STMT, _priv->preparedStatement);
        _priv->preparedStatement = nullptr;
    }

	if (_priv->connection != SQL_NULL_HDBC)
	{
		SQLDisconnect(_priv->connection);
		SQLFreeHandle(SQL_HANDLE_DBC, _priv->connection);
        _priv->connection = nullptr;
	}

	if (_priv->env != SQL_NULL_HENV)
	{
		SQLFreeHandle(SQL_HANDLE_ENV, _priv->env);
        _priv->env = nullptr;
	}

#endif
	_priv->closed = true;
}

//void ODBCAppender::ODBCAppenderPriv::setPreparedStatement(SQLHDBC con, Pool& p)
//{
//#if LOG4CXX_HAVE_ODBC
//	auto ret = SQLAllocHandle( SQL_HANDLE_STMT, con, &this->preparedStatement);
//	if (ret < 0)
//	{
//		throw SQLException( SQL_HANDLE_DBC, con, "Failed to allocate statement handle.", p);
//	}

//	SQLWCHAR* wsql;
//	encode(&wsql, this->sqlStatement, p);
//	ret = SQLPrepareW(this->preparedStatement, wsql, SQL_NTS);
//	if (ret < 0)
//	{
//		throw SQLException(SQL_HANDLE_STMT, this->preparedStatement, "Failed to prepare sql statement.", p);
//	}

//	int parameterNumber = 0;
//    for (auto& item : this->sqlFormatters)
//	{
//		++parameterNumber;
//		auto max_character_count = std::get<2>(item);
//		auto bufferSize = max_character_count * sizeof(wchar_t);
//		std::get<1>(item) = (wchar_t*) p.palloc(bufferSize + sizeof(wchar_t));
//		SQLLEN cbString = SQL_NTS;
//		auto ret = SQLBindParameter
//			( this->preparedStatement
//			, parameterNumber
//			, SQL_PARAM_INPUT
//            , SQL_STRING_TYPE  // ValueType
//			, SQL_DEFAULT  // ParameterType
//			, 0            // ColumnSize
//			, 0            // DecimalDigits
//			, std::get<1>(item)  // ParameterValuePtr
//			, bufferSize         // BufferLength
//            , &cbString          // StrLen_or_IndPtr
//			);
//		if (ret < 0)
//		{
//			throw SQLException(SQL_HANDLE_STMT, this->preparedStatement, "Failed to bind parameter", p);
//		}
//	}
//#endif
//}

//void ODBCAppender::ODBCAppenderPriv::setParameterValues(const spi::LoggingEventPtr& event, Pool& p)
//{
//    for (auto& item : this->sqlFormatters)
//	{
//		LogString sbuf;
//		std::get<0>(item)->format(event, sbuf, p);
//#if LOG4CXX_LOGCHAR_IS_WCHAR_T
//		std::wstring& tmp = sbuf;
//#else
//		std::wstring tmp;
//		Transcoder::encode(sbuf, tmp);
//#endif
//		if (auto dst = std::get<1>(item))
//		{
//			auto sz = std::max(std::get<2>(item), tmp.size());
//			std::memcpy(dst, tmp.data(), sz * sizeof(wchar_t));
//			dst[sz] = 0;
//		}
//	}
//}

void ODBCAppender::flushBuffer(Pool& p)
{
#if LOG4CXX_HAVE_ODBC
	for (auto& logEvent : _priv->buffer)
	{

        try
        {
            std::vector<LogString> formattedStrings;
            int parameterNumber = 1;
            for (auto& formatter : _priv->sqlFormatters){
                LogString append;
                formatter->format(logEvent, append, p);
//                std::wstring transcoded;
//                Transcoder::encode(append, transcoded);
                formattedStrings.push_back(append);
            }

            for(auto& wstr_value : formattedStrings){
                SQLLEN cbValue = wstr_value.length();
                auto ret = SQLBindParameter
                    ( _priv->preparedStatement
                    , parameterNumber
                    , SQL_PARAM_INPUT
                    , SQL_C_CHAR  // ValueType
                    , SQL_CHAR  // ParameterType
                    , 0            // ColumnSize
                    , 0            // DecimalDigits
                    , wstr_value.data()  // ParameterValuePtr
                    , wstr_value.length()         // BufferLength
                    , &cbValue          // StrLen_or_IndPtr
                    );
                if (ret < 0)
                {
                    SQLWCHAR errIdBuf[10];
                    memset(errIdBuf, 0, sizeof(errIdBuf));
                    SQLINTEGER i;
                    SQLWCHAR errMsgBuf[255];
                    SQLGetDiagRecW(SQL_HANDLE_STMT, _priv->preparedStatement, 1, errIdBuf, &i, errMsgBuf, 255, nullptr);
                    LogString errId = sqlwchar_to_logstring(errIdBuf);
                    LogString errMsg = sqlwchar_to_logstring(errMsgBuf);
                    LogString fullMsg = LOG4CXX_STR("Failed to bind parameter: ");
                    fullMsg.append(errId);
                    fullMsg.append(LOG4CXX_STR(":"));
                    fullMsg.append(errMsg);
                    _priv->errorHandler->error(LOG4CXX_STR("Failed to bind parameter"), std::exception(),
                        ErrorCode::FLUSH_FAILURE);
                    break;
                }
                parameterNumber++;
            }

            auto ret = SQLExecute(_priv->preparedStatement);
            if (ret < 0)
            {
                throw SQLException(SQL_HANDLE_STMT, _priv->preparedStatement, "Failed to execute prepared statement", p);
            }
		}
		catch (SQLException& e)
		{
			_priv->errorHandler->error(LOG4CXX_STR("Failed to execute sql"), e,
				ErrorCode::FLUSH_FAILURE);
		}

        SQLFreeStmt(_priv->preparedStatement, SQL_RESET_PARAMS);
	}
#endif

	// clear the buffer of reported events
	_priv->buffer.clear();
}

void ODBCAppender::setSql(const LogString& s)
{
    _priv->sqlStatement = s;
}

#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR_T || defined(WIN32) || defined(_WIN32)
void ODBCAppender::encode(wchar_t** dest, const LogString& src, Pool& p)
{
	*dest = Transcoder::wencode(src, p);
}
#endif

void ODBCAppender::encode(unsigned short** dest,
	const LogString& src, Pool& p)
{
    if(src.length() == 0){
        *dest = nullptr;
        return;
    }
	//  worst case double number of characters from UTF-8 or wchar_t
	*dest = (unsigned short*)
		p.palloc((src.size() + 1) * 2 * sizeof(unsigned short));
	unsigned short* current = *dest;

	for (LogString::const_iterator i = src.begin();
		i != src.end();)
	{
		unsigned int sv = Transcoder::decode(src, i);

		if (sv < 0x10000)
		{
			*current++ = (unsigned short) sv;
		}
		else
		{
			unsigned char u = (unsigned char) (sv >> 16);
			unsigned char w = (unsigned char) (u - 1);
			unsigned short hs = (0xD800 + ((w & 0xF) << 6) + ((sv & 0xFFFF) >> 10));
			unsigned short ls = (0xDC00 + (sv & 0x3FF));
			*current++ = (unsigned short) hs;
			*current++ = (unsigned short) ls;
		}
	}

	*current = 0;
}

const LogString& ODBCAppender::getSql() const
{
	return _priv->sqlStatement;
}

void ODBCAppender::setUser(const LogString& user)
{
	_priv->databaseUser = user;
}

void ODBCAppender::setURL(const LogString& url)
{
	_priv->databaseURL = url;
}

void ODBCAppender::setPassword(const LogString& password)
{
	_priv->databasePassword = password;
}

void ODBCAppender::setBufferSize(size_t newBufferSize)
{
	_priv->bufferSize = newBufferSize;
}

const LogString& ODBCAppender::getUser() const
{
	return _priv->databaseUser;
}

const LogString& ODBCAppender::getURL() const
{
	return _priv->databaseURL;
}

const LogString& ODBCAppender::getPassword() const
{
	return _priv->databasePassword;
}

size_t ODBCAppender::getBufferSize() const
{
	return _priv->bufferSize;
}

