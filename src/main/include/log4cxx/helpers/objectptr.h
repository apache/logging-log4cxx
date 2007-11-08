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

#ifndef _LOG4CXX_HELPERS_OBJECT_PTR_H
#define _LOG4CXX_HELPERS_OBJECT_PTR_H

#include <log4cxx/log4cxx.h>

//
//   Helgrind (race detection tool for Valgrind) will complain if pointer
//   is not initialized in an atomic operation.  Static analysis tools
//   (gcc's -Weffc++, for example) will complain if pointer is not initialized
//   in member initialization list.  The use of a macro allows quick
//   switching between the initialization styles.
//
#if LOG4CXX_HELGRIND
#define _LOG4CXX_OBJECTPTR_INIT(x) { T** pp = &p; ObjectPtrBase::exchange((void**) pp, x); 
#else
#define _LOG4CXX_OBJECTPTR_INIT(x) : p(x) {
#endif

namespace log4cxx
{
    namespace helpers
    {

        class LOG4CXX_EXPORT ObjectPtrBase {
        public:
            static void checkNull(const int& null);
            static void* exchange(void** destination, void* newValue);
        };


      /** smart pointer to a Object descendant */
        template<typename T> class ObjectPtrT
        {
        public:
         template<typename InterfacePtr> ObjectPtrT(const InterfacePtr& p1)
            _LOG4CXX_OBJECTPTR_INIT(0)             
             cast(p1);
         }


         ObjectPtrT(const int& null) 
                _LOG4CXX_OBJECTPTR_INIT(0)
                ObjectPtrBase::checkNull(null);
         }

         ObjectPtrT()
                _LOG4CXX_OBJECTPTR_INIT(0)
         }

         ObjectPtrT(T * p1)
                _LOG4CXX_OBJECTPTR_INIT(p1)
                if (this->p != 0)
                {
                    this->p->addRef();
                }
            }

         ObjectPtrT(const ObjectPtrT& p1)
                _LOG4CXX_OBJECTPTR_INIT(p1.p)
                if (this->p != 0)
                {
                    this->p->addRef();
                }
            }

            ~ObjectPtrT()
            {
              if (p != 0) {
                  p->releaseRef();
              }
            }

            // Operators
         template<typename InterfacePtr> ObjectPtrT& operator=(const InterfacePtr& p1)
         {
           cast(p1);
           return *this;
         }

         ObjectPtrT& operator=(const ObjectPtrT& p1) {
             T* newPtr = (T*) p1.p;
             if (newPtr != 0) {
                 newPtr->addRef();
             }
             T** pp = &p;
             void* oldPtr = ObjectPtrBase::exchange((void**) pp, newPtr);
             if (oldPtr != 0) {
                 ((T*) oldPtr)->releaseRef();
             }
            return *this;
         }

         ObjectPtrT& operator=(const int& null) //throw(IllegalArgumentException)
         {
                //
                //   throws IllegalArgumentException if null != 0
                //
                ObjectPtrBase::checkNull(null);
                T** pp = &p;
                void* oldPtr = ObjectPtrBase::exchange((void**) pp, 0);
                if (oldPtr != 0) {
                   ((T*) oldPtr)->releaseRef();
                }
                return *this;
         }

         ObjectPtrT& operator=(T* p1) {
              if (p1 != 0) {
                p1->addRef();
              }
              T** pp = &p;
              void* oldPtr = ObjectPtrBase::exchange((void**) pp, p1);
              if (oldPtr != 0) {
                 ((T*)oldPtr)->releaseRef();
              }
              return *this;
            }

            bool operator==(const ObjectPtrT& p1) const { return (this->p == p1.p); }
            bool operator!=(const ObjectPtrT& p1) const { return (this->p != p1.p); }
            bool operator==(const T* p1) const { return (this->p == p1); }
            bool operator!=(const T* p1) const { return (this->p != p1); }
            T* operator->() const {return (T*) p; }
            T& operator*() const {return (T&) *p; }
            operator T*() const {return (T*) p; }

            template<typename InterfacePtr> void cast(const InterfacePtr& p1)
            {
               T* newPtr = 0;
               if (p1 != 0)
               {
                  newPtr = reinterpret_cast<T*>(const_cast<void*>(p1->cast(T::getStaticClass())));
               }
               operator=(newPtr);
            }


        private:
            T * p;
        };

    }
}

#endif //_LOG4CXX_HELPERS_OBJECT_PTR_H
