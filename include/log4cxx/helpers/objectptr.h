/***************************************************************************
                          objectptr.h  -  class ObjectPtr
                             -------------------
    begin                : mer avr 16 2003
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

#ifndef _LOG4CXX_HELPERS_OBJECT_PTR_H
#define _LOG4CXX_HELPERS_OBJECT_PTR_H

#include <log4cxx/helpers/exception.h>

namespace log4cxx
{
    namespace helpers
    {
		/** smart pointer to a Object descendant */
        template<typename T> class ObjectPtrT
        {
        public:
 			template<typename InterfacePtr> ObjectPtrT(const InterfacePtr& p)
				: p(0)
			{
				cast(p);
			}

			// Disable conversion using ObjectPtrT* specialization of
			// template<typename InterfacePtr> ObjectPtrT(const InterfacePtr& p)
/*			template<> explicit ObjectPtrT(ObjectPtrT* const & p) throw(IllegalArgumentException)
			{
				if (p == 0)
				{
					throw IllegalArgumentException(String());
				}
				else
				{
					this->p = p->p;
                    this->p->addRef();
				}
			}*/

			ObjectPtrT(int null) //throw(IllegalArgumentException)
				: p(0)
			{
				if (null != 0)
				{

					throw IllegalArgumentException(String());
				}
			}

			ObjectPtrT() : p(0)
			{
			}

			ObjectPtrT(T * p) : p(p)
            {
                if (this->p != 0)
                {
                    this->p->addRef();
                }
            }

            ObjectPtrT(const ObjectPtrT& p) : p(p.p)
            {
                if (this->p != 0)
                {
                    this->p->addRef();
                }
            }

            ~ObjectPtrT()
            {
                if (this->p != 0)
                {
                    this->p->releaseRef();
                }
            }

            // Operators
			template<typename InterfacePtr> ObjectPtrT& operator=(const InterfacePtr& p)
			{
				cast(p);
				return *this;
			}

			ObjectPtrT& operator=(const ObjectPtrT& p)
            {
                if (this->p != p.p)
                {
                    if (this->p != 0)
                    {
                        this->p->releaseRef();
                    }

                    this->p = p.p;

                    if (this->p != 0)
                    {
                        this->p->addRef();
                    }
                }

				return *this;
            }

			ObjectPtrT& operator=(int null) //throw(IllegalArgumentException)
			{
				if (null != 0)
				{
					throw IllegalArgumentException(String());
				}

				if (this->p != 0)
                {
                    this->p->releaseRef();
					this->p = 0;
                }

				return *this;
			}

            ObjectPtrT& operator=(T* p)
            {
                if (this->p != p)
                {
                    if (this->p != 0)
                    {
                        this->p->releaseRef();
                    }

                    this->p = p;

                    if (this->p != 0)
                    {
                        this->p->addRef();
                    }
                }

				return *this;
            }

            bool operator==(const ObjectPtrT& p) const { return (this->p == p.p); }
            bool operator!=(const ObjectPtrT& p) const { return (this->p != p.p); }
            bool operator==(const T* p) const { return (this->p == p); }
            bool operator!=(const T* p) const { return (this->p != p); }
            T* operator->() const {return p; }
            T& operator*() const {return *p; }
            operator T*() const {return p; }

			template<typename InterfacePtr> void cast(const InterfacePtr& p)
			{
				if (this->p != 0)
                {
                    this->p->releaseRef();
					this->p = 0;
                }

				if (p != 0)
				{
					this->p = (T*)p->cast(T::getStaticClass());
					if (this->p != 0)
					{
						this->p->addRef();
					}
				}
			}


        public:
            T * p;
        };
    };
};

#endif //_LOG4CXX_HELPERS_OBJECT_PTR_H
