/***************************************************************************
                          socketimpl.h  -  class SocketImpl
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

#ifndef _LOG4CXX_HELPERS_SOCKET_IMPL
#define _LOG4CXX_HELPERS_SOCKET_IMPL

#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/inetaddress.h>
#include <log4cxx/helpers/exception.h>

namespace log4cxx
{
	namespace helpers
	{
		/** Signals that an I/O exception of some sort has occurred. This class
		is the general class of exceptions produced by failed or interrupted
		I/O operations.
		*/
		class IOException : public Exception
		{
		public:
			String getMessage() { return String(); }
		};

		/** Thrown to indicate that there is an error in the underlying
		protocol, such as a TCP error.
		*/
		class SocketException : public IOException
		{
		public:
			SocketException();
			String getMessage();

		protected:
			String message;
		};

		/** Signals that an error occurred while attempting to connect a socket
		to a remote address and port. Typically, the connection was refused
		remotely (e.g., no process is listening on the remote address/port).
		*/
		class ConnectException : public SocketException
		{
		};

		/** Signals that an error occurred while attempting to bind a socket to
		a local address and port. Typically, the port is in use, or the
		requested local address could not be assigned.
		*/
		class BindException : public SocketException
		{
		};

		/** Signals that an I/O operation has been interrupted. An
		InterruptedIOException is thrown to indicate that an input or output
		transfer has been terminated because the thread performing it was
		interrupted. The field bytesTransferred  indicates how many bytes were
		successfully transferred before the interruption occurred.
		*/
		class InterruptedIOException : public IOException
		{
		};

		/** Signals that a timeout has occurred on a socket read or accept.
		*/
		class SocketTimeoutException : public InterruptedIOException
		{
		};

		class SocketImpl;
		typedef helpers::ObjectPtrT<SocketImpl> SocketImplPtr;

		/** @brief Default Socket Implementation.

		This implementation does not implement any security check.
		*/
		class SocketImpl : public helpers::ObjectImpl
		{
		protected:
			/** The IP address of the remote end of this socket. */
			InetAddress address;

			/** The file descriptor object for this socket. */
			int fd;

			/** The local port number to which this socket is connected. */
			int localport;

			/** The port number on the remote host to which
			this socket is connected. */
			int port;

			int timeout;

		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(SocketImpl)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(SocketImpl)
			END_LOG4CXX_CAST_MAP()

			SocketImpl();
			~SocketImpl();
			
			/** @brief Accepts a connection.
			@param s the connection
			@throw SocketTimeoutException if a timeout was previously set with
			setSoTimeout and the timeout has been reached.
			@throw SocketException if an I/O error occurs when accepting the
			connection
			*/
			void accept(SocketImplPtr s);

			/** @brief Returns the number of bytes that can be read from this socket
			without blocking.
			@return the number of bytes that can be read from this socket
			without blocking.
			*/
			int available();

			/** Binds this socket to the specified port number
			on the specified host.
			@param host the host address
    		@param port the port number.
			@exception BindException if an I/O error occurs when binding this socket.
			*/
			void bind(InetAddress host, int port);

			/** Closes this socket. */
			void close();

			/**  Connects this socket to the specified port number
			on the specified host.
			*/
 			void connect(InetAddress address, int port);

			/** Connects this socket to the specified port on the named host. */
			void connect(const String& host, int port);

			/** Creates either a stream or a datagram socket. */
			void create(bool stream);

			/** Returns the value of this socket's fd field. */
			inline int getFileDescriptor() const
				{ return fd; }

			/** Returns the value of this socket's address field. */
			inline InetAddress getInetAddress() const
				{ return address; }

			/** Returns the value of this socket's localport field. */
			inline int getLocalPort() const
				{ return localport; }

			/** Returns the value of this socket's port field. */
			inline int getPort() const
				{ return port; }

			/** Sets the maximum queue length for incoming connection
			indications (a request to connect) to the count argument.
			*/
			void listen(int backlog);

			/** Returns the address and port of this socket as a String.
			*/
			String toString() const;

			size_t read(void * buf, size_t len);
			size_t write(const void * buf, size_t len);

			/** Retrive setting for SO_TIMEOUT.
			*/
			int getSoTimeout();

			/** Enable/disable SO_TIMEOUT with the specified timeout, in milliseconds.
			*/
			void setSoTimeout(int timeout);
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPERS_SOCKET_IMPL
