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

		class LOG4CXX_EXPORT EOFException : public Exception
		{
		};

		class LOG4CXX_EXPORT SocketInputStream : public ObjectImpl
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

			void read(void * buffer, size_t len) const;
			void read(unsigned int &value) const;
			void read(int &value) const;
			void read(unsigned long &value) const;
			void read(long &value) const;
			void read(String& value) const;
			// some read functions are missing ...

			/** Close the stream and dereference the socket.
			*/
			void close();

		protected:
			SocketPtr socket;
			size_t bufferSize;
			unsigned char * memBuffer;
			size_t currentPos;
			size_t maxPos;
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPERS_SOCKET_OUTPUT_STREAM_H
