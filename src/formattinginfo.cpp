/*
 * Copyright 1999,2005 The Apache Software Foundation.
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

#include <log4cxx/logstring.h>
#include <log4cxx/pattern/formattinginfo.h>
#include <limits.h>

 using namespace log4cxx;
 using namespace log4cxx::pattern;

 IMPLEMENT_LOG4CXX_OBJECT(FormattingInfo)

  /**
   * Creates new instance.
   * @param leftAlign left align if true.
   * @param minLength minimum length.
   * @param maxLength maximum length.
   */
FormattingInfo::FormattingInfo(
    const bool leftAlign, const int minLength, const int maxLength) :
    leftAlign(leftAlign),
    minLength(minLength),
    maxLength(maxLength) {
}

  /**
   * Gets default instance.
   * @return default instance.
   */
FormattingInfoPtr FormattingInfo::getDefault() {
    static FormattingInfoPtr def(new FormattingInfo(false, 0, INT_MAX));
    return def;
}

  /**
   * Adjust the content of the buffer based on the specified lengths and alignment.
   *
   * @param fieldStart start of field in buffer.
   * @param buffer buffer to be modified.
   */
void FormattingInfo::format(const int fieldStart, LogString& buffer) const {
    int rawLength = buffer.length() - fieldStart;

    if (rawLength > maxLength) {
      buffer.erase(buffer.begin() + fieldStart,
                   buffer.begin() + fieldStart + (rawLength - maxLength));
    } else if (rawLength < minLength) {
      if (leftAlign) {
        buffer.append(minLength - rawLength, LOG4CXX_STR(' '));
      } else {
        buffer.insert(fieldStart, minLength - rawLength, LOG4CXX_STR(' '));
      }
    }
  }
