/***************************************************************************
                          socketinputstream.h  -  SocketInputStream
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

#ifndef _LOG4CXX_HELPERS_SOCKET_INPUT_STREAM_H
#define _LOG4CXX_HELPERS_SOCKET_INPUT_STREAM_H

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/exception.h>

namespace log4cxx
{
	namespace helpers
	{
		class Socket;
		typedef ObjectPtrT<Socket> SocketPtr;

		class SocketInputStream;
		typedef ObjectPtrT<SocketInputStream> SocketInputStreamPtr;

		class EOFException : Exception
		{
		public:
			tstring getMessage() { return tstring(); }
		};

		class SocketInputStream : public ObjectImpl
		{
		private:
			static size_t DEFAULT_BUFFER_SIZE;

		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(SocketInputStream)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(SocketInputStream)
			END_LOG4CXX_CAST_MAP()

			SocketInputStream(SocketPtr socket);
			SocketInputStream(SocketPtr socket, size_t bufferSize);
			~SocketInputStream();

			void read(void * buffer, int len);
			void read(unsigned int &value);
			void read(int &value);
			void read(unsigned long &value);
			void read(long &value);
			void read(tstring& value);
			// some read functions are missing ...

			/** Close the stream and dereference the socket.
			*/
			void close();

		protected:
			SocketPtr socket;
			size_t bufferSize;
			unsigned char * memBuffer;
			int currentPos;
			int maxPos;
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPERS_SOCKET_OUTPUT_STREAM_H
