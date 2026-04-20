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
class Pool;
}

/**
* An abstract representation of file and directory path names.
*/
class LOG4CXX_EXPORT File
{
	public:
		/**
		*   Construct a new instance.
		*/
		File();
		/**
		*   Construct a new instance.  Use setPath to specify path using a LogString.
		* @param path file path in local encoding.
		*/
		File(const char* path);
		/**
		*   Construct a new instance.  Use setPath to specify path using a LogString.
		* @param path file path in current encoding.
		*/
		File(const std::string& path);
#if LOG4CXX_WCHAR_T_API
		/**
		*   Construct a new instance.  Use setPath to specify path using a LogString.
		* @param path file path.
		*/
		File(const wchar_t* path);
		/**
		*   Construct a new instance.  Use setPath to specify path using a LogString.
		* @param path file path.
		*/
		File(const std::wstring& path);
#endif
#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
		/**
		*   Construct a new instance.  Use setPath to specify path using a LogString.
		* @param path file path.
		*/
		File(const UniChar* path);
		/**
		*   Construct a new instance.  Use setPath to specify path using a LogString.
		* @param path file path.
		*/
		File(const std::basic_string<UniChar>& path);
#endif
#if LOG4CXX_CFSTRING_API
		/**
		*   Construct a new instance.  Use setPath to specify path using a LogString.
		* @param path file path.
		*/
		File(const CFStringRef& path);
#endif
		/**
		 *  Copy constructor.
		 */
		File(const File& src);
		/**
		 *  Assignment operator.
		 */
		File& operator=(const File& src);
		/**
		 *  Destructor.
		 */
		~File();

		/**
		 *  Determines if file exists.
		 *  @return true if file exists.
		 */
		bool exists() const;
		/**
		 *  Provides the length of the file.  May not be accurate if file is current open.
		 *  @return length of file.
		 */
		size_t length() const;
		/**
		 *  Provides the last modification date.
		 *  @return the filesystem time of last modification.
		 */
		log4cxx_time_t lastModified() const;
		/**
		 *  Provides the final portion of file path.
		 *  @return file name.
		 */
		LogString getName() const;
		/**
		 *  Provides the file path.
		 *  @return file path.
		 */
		LogString getPath() const;
		/**
		 *  Provides the file path.
		 *  @return file path.
		 */
		const char* getAPRPath() const;
		/**
		 *  Use \c newValue as the file path
		 */
		File& setPath(const LogString& newVAlue);

#if LOG4CXX_ABI_VERSION <= 15
		/**
		 *  Open this file.
		 *  See <a href="https://apr.apache.org/docs/apr/1.7/group__apr__file__io.html#gabda14cbf242fb4fe99055434213e5446">apr_file_open</a> for details.
		 *  @param file allocated APR file handle.
		 *  @param flags flags.
		 *  @param perm permissions.
		 *  @return APR_SUCCESS if successful.
		 * @deprecated This function is deprecated and will be removed in a future version.
		 */
		[[ deprecated( "open is no longer supported" ) ]]
		log4cxx_status_t open(apr_file_t** file, int flags,	int perm, helpers::Pool& p) const;
#endif

		/**
		 *   List files if current file is a directory.
		 *   @return list of files in this directory, operation of non-directory returns empty list.
		 */
		std::vector<LogString> list() const;

		/**
		 *   Delete this file.
		 *   @return true if file successfully deleted.
		 */
		bool deleteFile() const;
		/**
		 *   Rename this file.
		 *   @param dest new path for file.
		 *   @return true if file successfully renamed.
		 */
		bool renameTo(const File& dest) const;

		/**
		 *   Provides the path of parent directory.
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
		 * @param autoDelete If true, delete file upon destruction.
		 */
		void setAutoDelete(bool newValue);

		/**
		 * Provides the value of the autodelete setting.  If true, this file will be deleted when the
		 * destructor is called.
		 *
		 * @return True if the file is deleted upon destruction.
		 */
		bool getAutoDelete() const;

#if LOG4CXX_ABI_VERSION <= 15
		/// @deprecated This function is deprecated and will be removed in a future version.
		[[ deprecated( "Pool is no longer required" ) ]]
		bool exists(helpers::Pool& p) const;
		/// @deprecated This function is deprecated and will be removed in a future version.
		[[ deprecated( "Pool is no longer required" ) ]]
		size_t length(helpers::Pool& p) const;
		/// @deprecated This function is deprecated and will be removed in a future version.
		[[ deprecated( "Pool is no longer required" ) ]]
		log4cxx_time_t lastModified(helpers::Pool& p) const;
		/// @deprecated This function is deprecated and will be removed in a future version.
		[[ deprecated( "Pool is no longer required" ) ]]
		std::vector<LogString> list(helpers::Pool& p) const;
		/// @deprecated This function is deprecated and will be removed in a future version.
		[[ deprecated( "Pool is no longer required" ) ]]
		bool deleteFile(helpers::Pool& p) const;
		/// @deprecated This function is deprecated and will be removed in a future version.
		[[ deprecated( "Pool is no longer required" ) ]]
		bool renameTo(const File& dest, helpers::Pool& p) const;
		/// @deprecated This function is deprecated and will be removed in a future version.
		[[ deprecated( "Pool is no longer required" ) ]]
		LogString getParent(helpers::Pool& p) const;
		/// @deprecated This function is deprecated and will be removed in a future version.
		[[ deprecated( "Pool is no longer required" ) ]]
		bool mkdirs(helpers::Pool& p) const;
#endif
	private:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(FilePrivate, m_priv)
};
} // namespace log4cxx

#define LOG4CXX_FILE(name) File(name)

#endif // _LOG4CXX_FILE_H
