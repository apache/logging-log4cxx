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

namespace log4cxx
{
    namespace helpers
    {
		/** smart pointer to a Object descendant */
        template<class T> class ObjectPtr
        {
        public:
            ObjectPtr(T * p = 0) : p(p)
            {
                if (this->p != 0)
                {
                    this->p->addRef();
                }
            }

            ObjectPtr(const ObjectPtr& p) : p(p.p)
            {
                if (this->p != 0)
                {
                    this->p->addRef();
                }
            }

            ~ObjectPtr()
            {
                if (this->p != 0)
                {
                    this->p->releaseRef();
                }
            }

            // Operators
            ObjectPtr& operator=(const ObjectPtr& p)
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
            
            ObjectPtr& operator=(T* p)
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

            bool operator==(const ObjectPtr& p) const { return (this->p == p.p); }
            bool operator!=(const ObjectPtr& p) const { return (this->p != p.p); }
            bool operator==(const T* p) const { return (this->p == p); }
            bool operator!=(const T* p) const { return (this->p != p); }
            T* operator->() const {return p; }
            T& operator*() const {return *p; }
            operator T*() const {return p; }

        public:
            T * p;
        };
    };
};

#endif //_LOG4CXX_HELPERS_OBJECT_PTR_H
