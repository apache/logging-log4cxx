/*
 * Copyright 2003-2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <log4cxx/helpers/properties.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

class PropertyParser
{
public:
        void parse(LogString& in, Properties& properties)
        {
                LogString key, element;
                LexemType lexemType = BEGIN;
                logchar c;
                bool finished = false;

                if (!get(in, c))
                {
                        return;
                }

                while (!finished)
                {
                        switch(lexemType)
                        {
                        case BEGIN:
                                switch(c)
                                {
                                case LOG4CXX_STR(' '):
                                case LOG4CXX_STR('\t'):
                                case LOG4CXX_STR('\n'):
                                case LOG4CXX_STR('\r'):
                                        if (!get(in, c))
                                                finished = true;
                                        break;

                                case LOG4CXX_STR('#'):
                                case LOG4CXX_STR('!'):
                                        lexemType = COMMENT;
                                        if (!get(in, c))
                                                finished = true;
                                        break;

                                default:
                                        lexemType = KEY;
                                        break;
                                }
                                break;

                        case KEY:
                                switch(c)
                                {
                                case LOG4CXX_STR('\\'):
                                        lexemType = KEY_ESCAPE;
                                        if (!get(in, c))
                                                finished = true;
                                        break;

                                case LOG4CXX_STR('\t'):
                                case LOG4CXX_STR(' '):
                                case LOG4CXX_STR(':'):
                                case LOG4CXX_STR('='):
                                        lexemType = DELIMITER;
                                        if (!get(in, c))
                                                finished = true;
                                        break;

                                case LOG4CXX_STR('\n'):
                                case LOG4CXX_STR('\r'):
                                        // key associated with an empty string element
                                        properties.setProperty(key, LOG4CXX_STR(""));
                                        key.erase(key.begin(), key.end());
                                        lexemType = BEGIN;
                                        if (!get(in, c))
                                                finished = true;
                                        break;

                                default:
                                        key.append(1, c);
                                        if (!get(in, c))
                                                finished = true;
                                        break;
                                }
                                break;

                        case KEY_ESCAPE:
                                switch(c)
                                {
                                case LOG4CXX_STR('\t'):
                                case LOG4CXX_STR(' '):
                                case LOG4CXX_STR(':'):
                                case LOG4CXX_STR('='):
                                case LOG4CXX_STR('\\'):
                                        key.append(1, c);
                                        lexemType = KEY;
                                        if (!get(in, c))
                                                finished = true;
                                        break;

                                case LOG4CXX_STR('\n'):
                                        lexemType = KEY_CONTINUE;
                                        if (!get(in, c))
                                                finished = true;
                                        break;

                                case LOG4CXX_STR('\r'):
                                        lexemType = KEY_CONTINUE2;
                                        if (!get(in, c))
                                                finished = true;
                                        break;
                                }
                                break;

                        case KEY_CONTINUE:
                                switch(c)
                                {
                                case LOG4CXX_STR(' '):
                                case LOG4CXX_STR('\t'):
                                        if (!get(in, c))
                                                finished = true;
                                        break;

                                default:
                                        lexemType = KEY;
                                        break;
                                }
                                break;

                        case KEY_CONTINUE2:
                                switch(c)
                                {
                                case LOG4CXX_STR('\n'):
                                        if (!get(in, c))
                                                finished = true;
                                        lexemType = KEY_CONTINUE;
                                        break;

                                default:
                                        lexemType = KEY_CONTINUE;
                                        break;
                                }
                                break;

                        case DELIMITER:
                                switch(c)
                                {
                                case LOG4CXX_STR('\t'):
                                case LOG4CXX_STR(' '):
                                case LOG4CXX_STR(':'):
                                case LOG4CXX_STR('='):
                                        if (!get(in, c))
                                                finished = true;
                                        break;

                                default:
                                        lexemType = ELEMENT;
                                        break;
                                }
                                break;

                        case ELEMENT:
                                switch(c)
                                {
                                case LOG4CXX_STR('\\'):
                                        lexemType = ELEMENT_ESCAPE;
                                        if (!get(in, c))
                                                finished = true;
                                        break;

                                case LOG4CXX_STR('\n'):
                                case LOG4CXX_STR('\r'):
                                        // key associated with an empty string element
                                        properties.setProperty(key, element);
                                        key.erase(key.begin(), key.end());
                                        element.erase(element.begin(), element.end());
                                        lexemType = BEGIN;
                                        if (!get(in, c))
                                                finished = true;
                                        break;

                                default:
                                        element.append(1, c);
                                        if (!get(in, c))
                                                finished = true;
                                        break;
                                }
                                break;

                        case ELEMENT_ESCAPE:
                                switch(c)
                                {
                                case LOG4CXX_STR('t'):
                                case LOG4CXX_STR(' '):
                                case LOG4CXX_STR('n'):
                                case LOG4CXX_STR('r'):
                                case LOG4CXX_STR('\''):
                                case LOG4CXX_STR('\\'):
                                case LOG4CXX_STR('\"'):
                                case LOG4CXX_STR(':'):
                                default:
                                        element.append(1, c);
                                        lexemType = ELEMENT;
                                        if (!get(in, c))
                                                finished = true;
                                        break;

                                case LOG4CXX_STR('\n'):
                                        lexemType = ELEMENT_CONTINUE;
                                        if (!get(in, c))
                                                finished = true;
                                        break;

                                case LOG4CXX_STR('\r'):
                                        lexemType = ELEMENT_CONTINUE2;
                                        if (!get(in, c))
                                                finished = true;
                                        break;
                                }
                                break;

                        case ELEMENT_CONTINUE:
                                switch(c)
                                {
                                case LOG4CXX_STR(' '):
                                case LOG4CXX_STR('\t'):
                                        if (!get(in, c))
                                                finished = true;
                                        break;

                                default:
                                        lexemType = ELEMENT;
                                        break;
                                }
                                break;

                        case ELEMENT_CONTINUE2:
                                switch(c)
                                {
                                case LOG4CXX_STR('\n'):
                                        if (!get(in, c))
                                                finished = true;
                                        lexemType = ELEMENT_CONTINUE;
                                        break;

                                default:
                                        lexemType = ELEMENT_CONTINUE;
                                        break;
                                }
                                break;

                        case COMMENT:
                                if (c == LOG4CXX_STR('\n') || c == LOG4CXX_STR('\r'))
                                {
                                        lexemType = BEGIN;
                                }
                                if (!get(in, c))
                                        finished = true;
                                break;
                        }
                }

                if (!key.empty())
                {
                        properties.setProperty(key, element);
                }
        }

protected:
        bool get(LogString& in, logchar& c)
        {
                if (in.empty()) {
                    c = 0;
                    return false;
                }
                c = in[0];
                in.erase(in.begin());
                return true;
        }

        typedef enum
        {
                BEGIN,
                KEY,
                KEY_ESCAPE,
                KEY_CONTINUE,
                KEY_CONTINUE2,
                DELIMITER,
                ELEMENT,
                ELEMENT_ESCAPE,
                ELEMENT_CONTINUE,
                ELEMENT_CONTINUE2,
                COMMENT
        }
        LexemType;
};

LogString Properties::setProperty(const LogString& key, const LogString& value)
{
        LogString oldValue(properties[key]);
        properties[key] = value;
        //tcout << LOG4CXX_STR("setting property key=") << key << LOG4CXX_STR(", value=") << value << std::endl;
        return oldValue;
}

LogString Properties::getProperty(const LogString& key) const
{
        std::map<LogString, LogString>::const_iterator it = properties.find(key);
        return (it != properties.end()) ? it->second : LogString();
}

void Properties::load(LogString& inStream)
{
        properties.clear();
        PropertyParser parser;
        parser.parse(inStream, *this);
}

std::vector<LogString> Properties::propertyNames() const
{
        std::vector<LogString> names;
        names.reserve(properties.size());

        std::map<LogString, LogString>::const_iterator it;
        for (it = properties.begin(); it != properties.end(); it++)
        {
                const LogString& key = it->first;
                names.push_back(key);
        }

        return names;
}

