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

#include <log4cxx/logstring.h>
#include <log4cxx/helpers/properties.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <cctype>
#include <algorithm>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

template <typename Char>
struct Properties::Less
{
	bool operator()(const std::basic_string<Char>& str1, const std::basic_string<Char>& str2) const
	{
		return std::lexicographical_compare
			( str1.begin(), str1.end()
			, str2.begin(), str2.end()
			, [](Char c1, Char c2)
				{
					return std::tolower(static_cast<unsigned char>(c1)) < std::tolower(static_cast<unsigned char>(c2));
				}
			);
	}
};

class ISO_8859_1_CharIterator
{
	enum { BUFSIZE = 4096 };
	InputStreamPtr m_in;
	char           m_storage[BUFSIZE];
	ByteBuffer     m_buffer;

public: // ...structors
	ISO_8859_1_CharIterator(const InputStreamPtr& in)
		: m_in(in)
		, m_buffer(m_storage, BUFSIZE)
	{
		m_in->read(m_buffer);
		m_buffer.flip(); // Change m_buffer to a collection of bytes to be processed
	}

public: // Accessors
	/// The current item.
	/// @pre !off()
	uint32_t item() const
	{
		return static_cast<uint32_t>(*m_buffer.current());
	}

	/// Is this before the first item or after the last item?
	bool off() const
	{
		return 0 == m_buffer.remaining();
	}

public: // Modifiers
	/// Advance the iterator
	/// @pre !off()
	void forth()
	{
		m_buffer.increment_position(1);
		if (0 == m_buffer.remaining())
		{
			m_buffer.clear();
			m_in->read(m_buffer);
			m_buffer.flip(); // Change m_buffer to a collection of bytes to be processed
		}
	}
};

class PropertyParser
{
		ISO_8859_1_CharIterator m_in;
	public:
		PropertyParser(const InputStreamPtr& in)
			: m_in(in)
		{}

		void loadInto(Properties& properties)
		{
			LogString key, element;
			LexemType lexemType = BEGIN;
			logchar c;
			bool finished = false;

			if (!get(c))
			{
				return;
			}

			while (!finished)
			{
				if (1000 < key.size())
					throw IOException("property key exceeds 1000 characters");
				if (10000 < element.size())
					throw IOException("property value exceeds 10000 characters");
				switch (lexemType)
				{
					case BEGIN:
						switch (c)
						{
							case 0x20: // ' '
							case 0x09: // '\t'
							case 0x0A: // '\n'
							case 0x0D: // '\r'
								if (!get(c))
								{
									finished = true;
								}

								break;

							case 0x23: // '#'
							case 0x21: // '!'
								lexemType = COMMENT;

								if (!get(c))
								{
									finished = true;
								}

								break;

							default:
								lexemType = KEY;
								break;
						}

						break;

					case KEY:
						switch (c)
						{
							case 0x5C: // '\\'
								lexemType = KEY_ESCAPE;

								if (!get(c))
								{
									finished = true;
								}

								break;

							case 0x09: // '\t'
							case 0x20: // ' '
							case 0x3A: // ':'
							case 0x3D: // '='
								lexemType = DELIMITER;

								if (!get(c))
								{
									finished = true;
								}

								break;

							case 0x0A:
							case 0x0D:
								// key associated with an empty string element
								properties.setProperty(key, LogString());
								key.erase(key.begin(), key.end());
								lexemType = BEGIN;

								if (!get(c))
								{
									finished = true;
								}

								break;

							default:
								key.append(1, c);

								if (!get(c))
								{
									finished = true;
								}

								break;
						}

						break;

					case KEY_ESCAPE:
						switch (c)
						{
							case 0x74: // 't'
								key.append(1, 0x09);
								lexemType = KEY;
								break;

							case 0x6E: // 'n'
								key.append(1, 0x0A);
								lexemType = KEY;
								break;

							case 0x72: // 'r'
								key.append(1, 0x0D);
								lexemType = KEY;
								break;

							case 0x0A: // '\n'
								lexemType = KEY_CONTINUE;
								break;

							case 0x0D: // '\r'
								lexemType = KEY_CONTINUE2;
								break;

							default:
								key.append(1, c);
								lexemType = KEY;
						}

						if (!get(c))
						{
							finished = true;
						}

						break;

					case KEY_CONTINUE:
						switch (c)
						{
							case 0x20:  // ' '
							case 0x09: //  '\t'
								if (!get(c))
								{
									finished = true;
								}

								break;

							default:
								lexemType = KEY;
								break;
						}

						break;

					case KEY_CONTINUE2:
						switch (c)
						{
							case 0x0A: // '\n'
								if (!get(c))
								{
									finished = true;
								}

								lexemType = KEY_CONTINUE;
								break;

							default:
								lexemType = KEY_CONTINUE;
								break;
						}

						break;

					case DELIMITER:
						switch (c)
						{
							case 0x09: // '\t'
							case 0x20: // ' '
							case 0x3A: // ':'
							case 0x3D: // '='
								if (!get(c))
								{
									finished = true;
								}

								break;

							default:
								lexemType = ELEMENT;
								break;
						}

						break;

					case ELEMENT:
						switch (c)
						{
							case 0x5C: // '\\'
								lexemType = ELEMENT_ESCAPE;

								if (!get(c))
								{
									finished = true;
								}

								break;

							case 0x0A: // '\n'
							case 0x0D: // '\r'
								// key associated with an empty string element
								properties.setProperty(key, element);
								key.erase(key.begin(), key.end());
								element.erase(element.begin(), element.end());
								lexemType = BEGIN;

								if (!get(c))
								{
									finished = true;
								}

								break;

							default:
								element.append(1, c);

								if (!get(c))
								{
									finished = true;
								}

								break;
						}

						break;

					case ELEMENT_ESCAPE:
						switch (c)
						{
							case 0x74: // 't'
								element.append(1, 0x09);
								lexemType = ELEMENT;
								break;

							case 0x6E: // 'n'
								element.append(1, 0x0A);
								lexemType = ELEMENT;
								break;

							case 0x72: // 'r'
								element.append(1, 0x0D);
								lexemType = ELEMENT;
								break;

							case 0x0A: // '\n'
								lexemType = ELEMENT_CONTINUE;
								break;

							case 0x0D: // '\r'
								lexemType = ELEMENT_CONTINUE2;
								break;

							default:
								element.append(1, c);
								lexemType = ELEMENT;
								break;
						}

						if (!get(c))
						{
							finished = true;
						}

						break;

					case ELEMENT_CONTINUE:
						switch (c)
						{
							case 0x20: // ' '
							case 0x09: // '\t'
								if (!get(c))
								{
									finished = true;
								}

								break;

							default:
								lexemType = ELEMENT;
								break;
						}

						break;

					case ELEMENT_CONTINUE2:
						switch (c)
						{
							case 0x0A: // '\n'
								if (!get(c))
								{
									finished = true;
								}

								lexemType = ELEMENT_CONTINUE;
								break;

							default:
								lexemType = ELEMENT_CONTINUE;
								break;
						}

						break;

					case COMMENT:
						if (c == 0x0A || c == 0x0D)
						{
							lexemType = BEGIN;
						}

						if (!get(c))
						{
							finished = true;
						}

						break;
				}
			}

			if (!key.empty())
			{
				properties.setProperty(key, element);
			}
		}

	protected:
		bool get(logchar& c)
		{
			if (m_in.off())
			{
				c = 0;
				return false;
			}

			c = static_cast<logchar>(m_in.item());
			m_in.forth();
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

Properties::Properties() : properties(new PropertyMap())
{
}

Properties::Properties(const Properties& other)
	: properties(new PropertyMap(*other.properties))
{
}

Properties& Properties::operator=(const Properties& other)
{
	delete this->properties;
	this->properties = new PropertyMap(*other.properties);
	return *this;
}

Properties::~Properties()
{
	delete properties;
}

LogString Properties::setProperty(const LogString& key, const LogString& value)
{
	return put(key, value);
}

LogString Properties::put(const LogString& key, const LogString& value)
{
	LogString oldValue((*properties)[key]);
	(*properties)[key] = value;
	return oldValue;
}

LogString Properties::getProperty(const LogString& key) const
{
	return get(key);
}

LogString Properties::get(const LogString& key) const
{
	PropertyMap::const_iterator it = properties->find(key);
	return (it != properties->end()) ? it->second : LogString();
}

void Properties::load(const InputStreamPtr& inStream)
{
	PropertyParser(inStream).loadInto(*this);
}

std::vector<LogString> Properties::propertyNames() const
{
	std::vector<LogString> names;
	names.reserve(properties->size());

	for (auto const& item : *properties)
	{
		const LogString& key = item.first;
		names.push_back(key);
	}

	return names;
}

bool Properties::isEmpty() const
{
	return properties->empty();
}
