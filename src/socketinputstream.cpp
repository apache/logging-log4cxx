/***************************************************************************
           socketinputstream.cpp  -  class SocketInputStream
                             -------------------
    begin                : ven mai 9 2003
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

#include <log4cxx/helpers/socketinputstream.h>
#include <log4cxx/helpers/socket.h>
#include <log4cxx/helpers/loglog.h>

using namespace log4cxx;
using namespace log4cxx::helpers ;

size_t SocketInputStream::DEFAULT_BUFFER_SIZE = 32;

SocketInputStream::SocketInputStream(SocketPtr socket)
: socket(socket), bufferSize(DEFAULT_BUFFER_SIZE),
currentPos(0), maxPos(0)
{
	memBuffer = new unsigned char[bufferSize];
}

SocketInputStream::SocketInputStream(SocketPtr socket, size_t bufferSize)
: socket(socket), bufferSize(bufferSize),
currentPos(0), maxPos(0)
{
	memBuffer = new unsigned char[bufferSize];
}

SocketInputStream::~SocketInputStream()
{
	delete [] memBuffer;
}

void SocketInputStream::read(void * buf, int len)
{
//	LOGLOG_DEBUG(_T("SocketInputStream reading ") << len << _T(" bytes"));
	unsigned char * dstBuffer = (unsigned char *)buf;
	
	if (len <= maxPos - currentPos)
	{
//		LOGLOG_DEBUG(_T("SocketInputStream using cache buffer, currentPos=")
//			<< currentPos << _T(", maxPos=") << maxPos);
		memcpy(dstBuffer, memBuffer + currentPos, len);
		currentPos += len;
	}
	else
	{
//		LOGLOG_DEBUG(_T("SocketInputStream cache buffer too small"));

//		LOGLOG_DEBUG(_T("tmpBuffer=alloca(")
//			<< len - maxPos + currentPos + bufferSize << _T(")"));
			
		unsigned char * tmpBuffer
 			= (unsigned char *) alloca(len - maxPos + currentPos + bufferSize);

		size_t read = socket->read(tmpBuffer, len - maxPos + currentPos + bufferSize);

		if (read == 0)
		{
			throw EOFException();
		}

//		LOGLOG_DEBUG(_T("SocketInputStream currentPos:") << currentPos
//			<< _T(", maxPos:") << maxPos << _T(", read:") << read);

		if (maxPos - currentPos > 0)
		{
//			LOGLOG_DEBUG(_T("memcpy(dstBuffer, membuffer+") << currentPos
//				<< _T(",") << maxPos << _T("-") << currentPos << _T(")"));
			memcpy(dstBuffer, memBuffer + currentPos, maxPos - currentPos);
		}

		if (read <= len - maxPos + currentPos)
		{
//			LOGLOG_DEBUG(_T("SocketInputStream read <= len - maxPos + currentPos"));

//			LOGLOG_DEBUG(_T("memcpy(dstBuffer+") << maxPos - currentPos
//				<< _T(",tmpBuffer,") << read << _T(")"));
			memcpy(dstBuffer + maxPos - currentPos, tmpBuffer, read);
			currentPos = 0;
			maxPos = 0;
		}
		else
		{
//			LOGLOG_DEBUG(_T("memcpy(dstBuffer+") << maxPos - currentPos
//				<< _T(",tmpBuffer,") << len - maxPos + currentPos << _T(")"));
			memcpy(dstBuffer + maxPos - currentPos, tmpBuffer, len - maxPos + currentPos);

//			LOGLOG_DEBUG(_T("memcpy(memBuffer,tmpBuffer+")
//				<< len - maxPos + currentPos
//				<< _T(",") << read - len + maxPos - currentPos << _T(")"));
			memcpy(memBuffer,
				tmpBuffer + len - maxPos + currentPos,
				read - len + maxPos - currentPos);

//			LOGLOG_DEBUG(_T("maxPos=") << read - len + maxPos - currentPos);
			maxPos = read - len + maxPos - currentPos;
			currentPos = 0;
		}
	}
}

void SocketInputStream::read(unsigned int& value)
{
	read(&value, sizeof(value));
//	LOGLOG_DEBUG(_T("unsigned int read:") << value);
}

void SocketInputStream::read(int& value)
{
	read(&value, sizeof(value));
//	LOGLOG_DEBUG(_T("int read:") << value);
}

void SocketInputStream::read(unsigned long& value)
{
	read(&value, sizeof(value));
//	LOGLOG_DEBUG(_T("unsigned long read:") << value);
}

void SocketInputStream::read(long& value)
{
	read(&value, sizeof(value));
//	LOGLOG_DEBUG(_T("long read:") << value);
}

void SocketInputStream::read(tstring& value)
{
	tstring::size_type size = 0;

	read(&size, sizeof(tstring::size_type));
//	LOGLOG_DEBUG(_T("string size read:") << size);

	if (size > 0)
	{
		if (size > 1024)
		{
			throw SocketException();
		}
		
		TCHAR * buffer;
		buffer = (TCHAR *)alloca((size + 1)* sizeof(TCHAR));
		buffer[size] = _T('\0');
		read(buffer, size * sizeof(TCHAR));
		value = buffer;
	}
	
//	LOGLOG_DEBUG(_T("string read:") << value);
}

void SocketInputStream::close()
{
	// seek to begin
	currentPos = 0;

	// dereference socket
	socket = 0;
}
