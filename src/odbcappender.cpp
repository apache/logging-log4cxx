/***************************************************************************
                          odbcappender.cpp  -  class ODBCAppender
                             -------------------
    begin                : jeu mai 8 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#include <log4cxx/db/odbcappender.h>

#ifdef HAVE_ODBC

#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/patternlayout.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::db;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(ODBCAppender)

ODBCAppender::ODBCAppender()
: connection(SQL_NULL_HDBC), env(SQL_NULL_HENV), bufferSize(1)
{
}

ODBCAppender::~ODBCAppender()
{
	finalize();
}

void ODBCAppender::append(const spi::LoggingEvent& event)
{
	buffer.push_back(event);
	
	if (buffer.size() >= bufferSize)
		flushBuffer();
}

tstring ODBCAppender::getLogStatement(const spi::LoggingEvent& event)
{
	tostringstream sbuf;
	getLayout()->format(sbuf, event);
	return sbuf.str();
}

void ODBCAppender::execute(const tstring& sql)
{
	SQLRETURN ret;
	SQLHDBC con = SQL_NULL_HDBC;
	SQLHSTMT stmt = SQL_NULL_HSTMT;

	try
	{
		con = getConnection();
		
		ret = SQLAllocHandle(SQL_HANDLE_STMT, con, &stmt);
		if (ret < 0)
		{
			throw SQLException(ret);
		}

		ret = SQLExecDirect(stmt, (SQLTCHAR *)sql.c_str(), SQL_NTS);
		if (ret < 0)
		{
			throw SQLException(ret);
		}
	} 
	catch (SQLException& e)
	{
		UCHAR plm_szSqlState[256] = "", plm_szErrorMsg[256] = "";
		SDWORD plm_pfNativeError = 0L;
		SWORD plm_pcbErrorMsg = 0;

		SQLGetDiagRec(SQL_HANDLE_STMT, stmt, 1, plm_szSqlState, &plm_pfNativeError,
			plm_szErrorMsg, 255, &plm_pcbErrorMsg);

		if (stmt != SQL_NULL_HSTMT)
		{
			SQLFreeHandle(SQL_HANDLE_STMT, stmt);
		}

		throw e;
	}
	SQLFreeHandle(SQL_HANDLE_STMT, stmt);
	closeConnection(con);
	
	//tcout << _T("Execute: ") << sql << std::endl;
}

/* The default behavior holds a single connection open until the appender
is closed (typically when garbage collected).*/
void ODBCAppender::closeConnection(SQLHDBC con)
{
}

SQLHDBC ODBCAppender::getConnection()
{
	SQLRETURN ret;

	if (env == SQL_NULL_HENV)
	{
		ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
		if (ret < 0)
		{
			env = SQL_NULL_HENV;
			throw SQLException(ret);
		}
		
		ret = SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER) SQL_OV_ODBC3, SQL_IS_INTEGER);
		if (ret < 0)
		{
			SQLFreeHandle(SQL_HANDLE_ENV, env);
			env = SQL_NULL_HENV;
			throw SQLException(ret);
		}
	}
	
	if (connection == SQL_NULL_HDBC)
	{
		ret = SQLAllocHandle(SQL_HANDLE_DBC, env, &connection);
		if (ret < 0)
		{
			connection = SQL_NULL_HDBC;
			throw SQLException(ret);
		}


		ret = SQLConnect(connection,
			(SQLTCHAR *)databaseURL.c_str(), SQL_NTS,
			(SQLTCHAR *)databaseUser.c_str(), SQL_NTS, 
			(SQLTCHAR *)databasePassword.c_str(), SQL_NTS);
		if (ret < 0)
		{
			SQLFreeHandle(SQL_HANDLE_DBC, connection);
			connection = SQL_NULL_HDBC;
			throw SQLException(ret);
		}
	}
	
	return connection;
}

void ODBCAppender::close()
{
	try
	{
		flushBuffer();
	} 
	catch (SQLException& e)
	{
		errorHandler->error(_T("Error closing connection"), e, ErrorCode::GENERIC_FAILURE);
	}

	if (connection != SQL_NULL_HDBC)
	{
		SQLDisconnect(connection);
		SQLFreeHandle(SQL_HANDLE_DBC, connection);
	}
	
	if (env != SQL_NULL_HENV)
	{
		SQLFreeHandle(SQL_HANDLE_ENV, env);
	}
	
	this->closed = true;
}


void ODBCAppender::flushBuffer()
{
	//Do the actual logging
	//removes.ensureCapacity(buffer.size());

	std::list<spi::LoggingEvent>::iterator i;
	for (i = buffer.begin(); i != buffer.end(); i++)
	{
		try
		{
			const LoggingEvent& logEvent = *i;
			tstring sql = getLogStatement(logEvent);
			execute(sql);
		}
		catch (SQLException& e)
		{
			errorHandler->error(_T("Failed to excute sql"), e,
				ErrorCode::FLUSH_FAILURE);
		}
	}
	
	// clear the buffer of reported events
	buffer.clear();
}

void ODBCAppender::setSql(const tstring& s)
{
	sqlStatement = s;
	if (getLayout() == 0)
	{
		this->setLayout(new PatternLayout(s));
	}
	else
	{
		PatternLayoutPtr patternLayout = this->getLayout();
		if (patternLayout != 0)
		{
			patternLayout->setConversionPattern(s);
		}
	}
}

#endif //HAVE_ODBC
