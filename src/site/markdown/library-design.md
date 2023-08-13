Library Design Notes {#library-design}
===
<!--
 Note: License header cannot be first, as doxygen does not generate
 cleanly if it before the '==='
-->
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

With version 1.0.0 of Log4cxx, the library is designed to be ABI stable, such
that any internal changes to classes will not cause client code to break.
In order to do this, there are a few patterns that are used in order to make
sure that it stays stable.

# Use of class-specific structs to hold data.

This looks like the following in a header file:

```
class SomeClass {
public:
  SomeClass();
  ~SomeClass();

private:
  struct SomeClassPriv;
  std::unique_ptr<SomeClassPriv> m_priv;
}
```

In the .cpp file, you then can define it and use it like the following:

```
struct SomeClass::SomeClassPriv {
    int someMemberVariable;
};

SomeClass::SomeClass() :
    m_priv(std::make_unique<SomeClassPriv>()){}
```

This ensures that if new members need to be added to a class, or old ones removed,
the size of the class will not change.

# Inheriting classes with private data

Because subclasses no longer have direct access to their parents' variables,
a slight variation is used to allow subclasses to access parental variables,
and to ensure that the parent only stores one pointer.  This results in a
separate hierarchy for the private data from the hierarchy of the class.

This can be done to any depth that is required.

## Example

parent\_priv.h:
```
#include "parent.h"

struct Parent::ParentPrivate{
  int parentVariable;
};
```

parent.h:
```
class Parent {
pubic:
  struct ParentPrivate;
  Parent( std::unique_ptr<ParentPrivate> priv );
  virtual ~Parent();

protected:
  std::unique_ptr<ParentPrivate> m_priv;
};
```

parent.cpp:
```
#include "parent_priv.h"

Parent::Parent( std::unique_ptr<ParentPrivate> priv ) :
  m_priv( std::move(priv) ){}
```

child.h:
```
#include "parent.h"

class Child : public Parent {
public:
  Child();
  ~Child();

  void example();

private:
  struct ChildPriv;
};
```

child.cpp:
```
#include "parent_priv.h"
#include "child.h"

struct Child::ChildPriv : public Parent::ParentPriv {
  int childVariable;
};

Child::Child() : Parent(std::make_unique<ChildPriv>() ){}

void Child::example(){
  m_priv->parentVariable = ... ; // Can access parent variable via m_priv
  static_cast<ChildPriv*>(m_priv.get())->childVariable = ... ; // Must static_cast to access child
}
```

Caveats with this approach:
* All variables effectively become protected.  If they must be private for
some reason, you could probably make the Priv struct be a friend class.

# See Also

Qt documentation on D-Pointers, which this pattern is based off of: 
https://wiki.qt.io/D-Pointer
