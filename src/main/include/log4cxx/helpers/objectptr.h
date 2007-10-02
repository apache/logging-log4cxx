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
// Note:
// The LOG4CXX_HELGRIND conditional sections are due to conflicting
// demands of two diagnostic tools.  The -Weffc++ option for the GCC
// compiler wants the wrapped pointer to be initialized in
// the member initialization list.
// However, the Helgrind race condition tool for Valgrind will report
// that the wrapped pointer written outside of a synchronization
// block.  The member initialization approach is more efficient
// and should be safe since existing usage patterns should prevent
// the pointer to be available to other threads until after 
// construction is complete.
//
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
#if LOG4CXX_HELGRIND
         {
             ObjectPtrBase::exchange((void**) &p, 0);
#else
         : p(0) {
#endif
             cast(p1);
         }


         ObjectPtrT(const int& null) //throw(IllegalArgumentException)
#if LOG4CXX_HELGRIND
         {
                ObjectPtrBase::exchange((void**) &p, 0);
#else
         : p(0) {
#endif
                ObjectPtrBase::checkNull(null);
         }

         ObjectPtrT()
#if LOG4CXX_HELGRIND
         {
                ObjectPtrBase::exchange((void**) &p, 0);
#else
         : p(0) {
#endif
         }

         ObjectPtrT(T * p1)
#if LOG4CXX_HELGRIND
            {
                ObjectPtrBase::exchange((void**) &p, p1);
#else
         : p(p1) {
#endif
                if (this->p != 0)
                {
                    this->p->addRef();
                }
            }

            ObjectPtrT(const ObjectPtrT& p1)
#if LOG4CXX_HELGRIND
            {
                ObjectPtrBase::exchange((void**) &p, p1.p);
#else
            : p(p1.p) {
#endif
                if (this->p != 0)
                {
                    this->p->addRef();
                }
            }

            ~ObjectPtrT()
            {
              void* oldPtr = ObjectPtrBase::exchange((void**) &p, 0);
              if (oldPtr != 0) {
                  ((T*) oldPtr)->releaseRef();
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
             void* oldPtr = ObjectPtrBase::exchange((void**) &p, newPtr);
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
                void* oldPtr = ObjectPtrBase::exchange((void**) &p, 0);
                if (oldPtr != 0) {
                   ((T*) oldPtr)->releaseRef();
                }
                return *this;
         }

         ObjectPtrT& operator=(T* p1) {
              if (p1 != 0) {
                p1->addRef();
              }
              void* oldPtr = ObjectPtrBase::exchange((void**) &p, p1);
              if (oldPtr != 0) {
                 ((T*)oldPtr)->releaseRef();
              }
              return *this;
            }

            bool operator==(const ObjectPtrT& p1) const { return (this->p == p1.p); }
            bool operator!=(const ObjectPtrT& p1) const { return (this->p != p1.p); }
            bool operator==(const T* p1) const { return (this->p == p1); }
            bool operator!=(const T* p1) const { return (this->p != p1); }
            T* operator->() {return (T*) p; }
            const T* operator->() const {return (const T*) p; }
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
