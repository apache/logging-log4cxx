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

#ifndef _LOG4CXX_FILE_H
#define _LOG4CXX_FILE_H

#include <log4cxx/logger.h>
#include <log4cxx/logstring.h>

extern "C" {
	struct apr_file_t;
	struct apr_finfo_t;
}

namespace LOG4CXX_NS
{
namespace helpers
{
class Transcoder;
}

/**
* Holds the path to a file or directory.
*/
class LOG4CXX_EXPORT File
{
	public:
		/**
		*   An empty path.
		*/
		File();
		/**
		*   The file or directory at \c path.
		*/
		File(const char* path);
		/**
		*   The file or directory at \c path.
		*/
		File(const std::string& path);
#if LOG4CXX_WCHAR_T_API
		/**
		*   The file or directory at \c path.
		*/
		File(const wchar_t* path);
		/**
		*   The file or directory at \c path.
		*/
		File(const std::wstring& path);
#endif
#if LOG4CXX_CFSTRING_API
		/**
		*   The file or directory at \c path.
		*/
		File(const CFStringRef& path);
#endif
		/**
		 *  A copy of \c other.
		 */
		File(const File& other);
		/**
		 *  Replace this with \c other
		 */
		File& operator=(const File& other);
		/**
		 *  Release resouces used by this.
		 */
		~File();

		/**
		 *  Has a path been set?
		 *  @return true if the file name is not empty.
		 */
		bool hasPath() const;
		/**
		 *  Is this a path to an existing file or directory?
		 */
		bool exists() const;
		/**
		 *  The size in bytes of the file indicated by this.
		 *  May not be accurate if file is current open.
		 */
		size_t length() const;
		/**
		 *  The microseconds since 1970-01-01 when the file indicated by this was last modified.
		 */
		log4cxx_time_t lastModified() const;
		/**
		 *  The final portion of the file or directory path.
		 */
		LogString getName() const;
		/**
		 *  The full file or directory path.
		 */
		LogString getPath() const;
		/**
		 *  The full file or directory path encoded for APR use.
		 */
		const char* getAPRPath() const;
		/**
		 *  Use \c newValue as the file path
		 */
		File& setPath(const LogString& newValue);


		/**
		 *   A list of files if this is a directory, otherwise an empty list.
		 */
		std::vector<LogString> list() const;

		/**
		 *   Attempt to remove this file or directory from persistent storage.
		 *   @return true if file successfully deleted.
		 */
		bool deleteFile() const;
		/**
		 *   Move this file or directory to the path in \c newValue.
		 *   @return true if file successfully renamed.
		 */
		bool renameTo(const File& newValue) const;

		/**
		 *   The path without the final portion.
		 *   @return path of parent directory.
		 */
		LogString getParent() const;
		/**
		 *  Create the directories required for this file path.
		 *  @return true if all requested directories existed or have been created.
		 */
		bool mkdirs() const;

		/**
		 * Use \c newValue for whether the file is to be deleted when this object is destroyed.
		 * @param newValue If true, delete file upon destruction.
		 */
		void setAutoDelete(bool newValue);

		/**
		 * The value of the autodelete setting.  If true, this file will be deleted when the
		 * destructor is called.
		 *
		 * @return True if the file is deleted upon destruction.
		 */
		bool getAutoDelete() const;

	private:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(FilePrivate, m_priv)
};
} // namespace log4cxx

#define LOG4CXX_FILE(name) File(name)

#endif // _LOG4CXX_FILE_H
