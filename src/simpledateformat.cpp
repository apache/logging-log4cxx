/*
 * Copyright 2003,2004 The Apache Software Foundation.
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

#include <log4cxx/helpers/simpledateformat.h>

#include <apr_time.h>
#include <apr_strings.h>
#include <sstream>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

using namespace std;


SimpleDateFormat::PatternToken::PatternToken() {
}

SimpleDateFormat::PatternToken::~PatternToken() {
}

void SimpleDateFormat::PatternToken::setTimeZone(const TimeZonePtr& zone) {
}


void SimpleDateFormat::PatternToken::renderFacet(const std::locale& locale,
                                                          std::basic_ostream<wchar_t>& buffer,
                                                          const tm* time,
                                                          const char spec) {
#if _MSC_VER < 1300
                _USE(locale, TimePutFacet).put(buffer,
                                 buffer, time, spec);
#else
                std::use_facet<TimePutFacet>(locale).put(buffer,
                                 buffer, buffer.fill(), time, spec);
#endif

}

namespace log4cxx {
  namespace helpers {
    namespace SimpleDateFormatImpl {

      class LiteralToken : public SimpleDateFormat::PatternToken {
      public:
        LiteralToken(wchar_t ch, int count) : ch(ch), count(count) {
        }
        void format(std::wstring& s, const apr_time_exp_t& tm, Pool& p) const {
          s.append(count, ch);
        }

      private:
        wchar_t ch;
        int count;
      };

      class EraToken : public SimpleDateFormat::PatternToken {
      public:
          EraToken(int count, const std::locale& locale)  {
          }
          void format(std::wstring& s, const apr_time_exp_t& tm, Pool& p) const {
             s.append(L"AD");
          }
     };


      class NumericToken : public SimpleDateFormat::PatternToken {
      public:
        NumericToken(size_t width)
            : width(width) {
        }

        virtual int getField(const apr_time_exp_t& tm) const = 0;

        void format(std::wstring& s, const apr_time_exp_t& tm, Pool& p) const {
          size_t initialLength = s.length();
          StringHelper::toString(getField(tm), p, s);
          size_t finalLength = s.length();
          size_t padding = width - (finalLength - initialLength);
          if (padding > 0) {
            s.insert(initialLength, padding, L'0');
          }
        }

      private:
        size_t width;
        char zeroDigit;
      };

      class YearToken : public NumericToken {
      public:
        YearToken(int width) : NumericToken(width) {
        }

        int getField(const apr_time_exp_t& tm) const {
          return 1900 + tm.tm_year;
        }
      };

      class MonthToken : public NumericToken {
      public:
        MonthToken(int width) : NumericToken(width) {
        }

        int getField(const apr_time_exp_t& tm) const {
          return tm.tm_mon + 1;
        }
      };

      class AbbreviatedMonthNameToken : public SimpleDateFormat::PatternToken {
      public:
        AbbreviatedMonthNameToken(int width, const std::locale& locale) : names(12) {
          tm time;
          memset(&time, sizeof(time), 0);
          std::basic_ostringstream<wchar_t> buffer;
          size_t start = 0;
          for (int imon = 0; imon < 12; imon++) {
             time.tm_mon = imon;
             renderFacet(locale, buffer, &time, 'b');
             std::wstring monthnames(buffer.str());
             names[imon] = monthnames.substr(start);
             start = monthnames.length();
          }
        }

        void format(std::wstring& s, const apr_time_exp_t& tm, Pool& p) const {
          s.append(names[tm.tm_mon]);
        }

      private:
        std::vector<std::wstring> names;

      };

      class FullMonthNameToken : public SimpleDateFormat::PatternToken {
      public:
        FullMonthNameToken(int width, const std::locale& locale) : names(12) {
          tm time;
          memset(&time, sizeof(time), 0);
          std::basic_ostringstream<wchar_t> buffer;
          size_t start = 0;
          for (int imon = 0; imon < 12; imon++) {
             time.tm_mon = imon;
             renderFacet(locale, buffer, &time, 'B');
             std::wstring monthnames(buffer.str());
             names[imon] = monthnames.substr(start);
             start = monthnames.length();
          }
        }

        void format(std::wstring& s, const apr_time_exp_t& tm, Pool& p) const {
          s.append(names[tm.tm_mon]);
        }

      private:
        std::vector<std::wstring> names;

      };

      class WeekInYearToken : public NumericToken {
      public:
          WeekInYearToken(int width) : NumericToken(width) {
          }

          int getField(const apr_time_exp_t& tm) const {
             return tm.tm_yday / 7;
          }
      };

      class WeekInMonthToken : public NumericToken {
      public:
          WeekInMonthToken(int width) : NumericToken(width) {
          }

          int getField(const apr_time_exp_t& tm) const {
             return tm.tm_mday / 7;
          }
      };


      class DayInMonthToken : public NumericToken {
      public:
          DayInMonthToken(int width) : NumericToken(width) {
          }

          int getField(const apr_time_exp_t& tm) const {
             return tm.tm_mday;
          }
      };

      class DayInYearToken : public NumericToken {
      public:
          DayInYearToken(int width) : NumericToken(width) {
          }

          int getField(const apr_time_exp_t& tm) const {
             return tm.tm_yday;
          }
      };


      class DayOfWeekInMonthToken : public NumericToken {
      public:
           DayOfWeekInMonthToken(int width) : NumericToken(width) {
           }

           int getField(const apr_time_exp_t& tm) const {
               return -1;
           }
      };

      class AbbreviatedDayNameToken : public SimpleDateFormat::PatternToken {
      public:
          AbbreviatedDayNameToken(int width, const std::locale& locale) : names(7) {
             tm time;
             memset(&time, sizeof(time), 0);
             std::wostringstream buffer;
             size_t start = 0;
             for (int iday = 0; iday < 7; iday++) {
                time.tm_wday = iday;
                renderFacet(locale, buffer, &time, 'a');
                std::wstring daynames(buffer.str());
                names[iday] = daynames.substr(start);
                start = daynames.length();
             }
          }

         void format(std::wstring& s, const apr_time_exp_t& tm, Pool& p) const {
            s.append(names[tm.tm_wday]);
         }

        private:
            std::vector<std::wstring> names;

        };

        class FullDayNameToken : public SimpleDateFormat::PatternToken {
        public:
          FullDayNameToken(int width, const std::locale& locale) : names(7) {
            tm time;
            memset(&time, sizeof(time), 0);
            std::basic_ostringstream<wchar_t> buffer;
            size_t start = 0;
            for (int iday = 0; iday < 7; iday++) {
               time.tm_wday = iday;
               renderFacet(locale, buffer, &time, 'A');
               std::wstring daynames(buffer.str());
               names[iday] = daynames.substr(start);
               start = daynames.length();
            }
          }

          void format(std::wstring& s, const apr_time_exp_t& tm, Pool& p) const {
            s.append(names[tm.tm_wday]);
          }

        private:
          std::vector<std::wstring> names;

        };


      class MilitaryHourToken : public NumericToken {
          public:
          MilitaryHourToken(int width, int offset) :
             NumericToken(width), offset(offset) {
          }

          int getField(const apr_time_exp_t& tm) const {
               return tm.tm_hour + offset;
          }

          private:
          int offset;
      };

      class HourToken : public NumericToken {
      public:
          HourToken(int width, int offset) : NumericToken(width) {
          }

          int getField(const apr_time_exp_t& tm) const {
              return ((tm.tm_hour + 12 - offset) % 12) + offset;
          }

          private:
          int offset;
      };

     class MinuteToken : public NumericToken {
     public:
          MinuteToken(int width) : NumericToken(width) {
          }

          int getField(const apr_time_exp_t& tm) const {
             return tm.tm_min;
          }
    };

    class SecondToken : public NumericToken {
    public:
         SecondToken(int width) : NumericToken(width) {
         }

         int getField(const apr_time_exp_t& tm) const {
            return tm.tm_sec;
         }
    };

    class MillisecondToken : public NumericToken {
    public:
          MillisecondToken(int width) : NumericToken(width) {
          }

          int getField(const apr_time_exp_t& tm) const {
             return tm.tm_usec / 1000;
          }
    };

    class AMPMToken : public SimpleDateFormat::PatternToken  {
    public:
        AMPMToken(int width, const std::locale& locale) : names(2)  {
          tm time;
          memset(&time, sizeof(time), 0);
          std::basic_ostringstream<wchar_t> buffer;
          size_t start = 0;
          for (int i = 0; i < 2; i++) {
             time.tm_hour = i * 12;
             renderFacet(locale, buffer, &time, 'p');
             std::wstring ampm = buffer.str();
             names[i] = ampm.substr(start);
             start = ampm.length();
          }
        }

        void format(std::wstring& s, const apr_time_exp_t& tm, Pool& p) const {
           s.append(names[tm.tm_hour / 12]);
        }

        private:
        std::vector<std::wstring> names;
    };


    class GeneralTimeZoneToken : public SimpleDateFormat::PatternToken  {
    public:
        GeneralTimeZoneToken(int width)  {
        }

        void format(std::wstring& s, const apr_time_exp_t& tm, Pool& p) const {
           LOG4CXX_ENCODE_WCHAR(tzID, timeZone->getID());
           s.append(tzID);
        }

        void setTimeZone(const TimeZonePtr& zone) {
          timeZone = zone;
        }

        private:
        TimeZonePtr timeZone;
    };

    class RFC822TimeZoneToken : public SimpleDateFormat::PatternToken  {
    public:
        RFC822TimeZoneToken(int width)  {
        }

        void format(std::wstring& s, const apr_time_exp_t& tm, Pool& p) const {
           if (tm.tm_gmtoff == 0) {
             s.append(1, L'Z');
           } else {
             apr_int32_t off = tm.tm_gmtoff;
             size_t basePos = s.length();
             s.append(L"+0000");
             if (off < 0) {
               s[basePos] = L'-';
               off = -off;
             }
             std::wstring hours;
             StringHelper::toString(off/3600, p, hours);
             size_t hourPos = basePos + 2;
             //
             //   assumes that point values for 0-9 are same between char and wchar_t
             //
             for (size_t i = hours.length(); i-- > 0;) {
               s[hourPos--] = hours[i];
             }
             std::wstring min;
             StringHelper::toString((off % 3600) / 60, p, min);
             size_t minPos = basePos + 4;
             //
             //   assumes that point values for 0-9 are same between char and wchar_t
             //
             for (size_t j = min.length(); j-- > 0;) {
               s[minPos--] = min[j];
             }
           }
        }
    };


    }
  }
}


SimpleDateFormat::SimpleDateFormat(const LogString& fmt)
  : timeZone(TimeZone::getDefault()) {
  std::locale defaultLocale;
  parsePattern(fmt, defaultLocale, pattern);
  for(PatternTokenList::iterator iter = pattern.begin();
      iter != pattern.end();
      iter++) {
      (*iter)->setTimeZone(timeZone);
  }
}

SimpleDateFormat::SimpleDateFormat(const LogString& fmt, const std::locale& locale)
  : timeZone(TimeZone::getDefault()) {
    parsePattern(fmt, locale, pattern);
    for(PatternTokenList::iterator iter = pattern.begin();
        iter != pattern.end();
        iter++) {
        (*iter)->setTimeZone(timeZone);
    }
}


SimpleDateFormat::~SimpleDateFormat() {
  for(PatternTokenList::iterator iter = pattern.begin();
      iter != pattern.end();
      iter++) {
      delete *iter;
  }
}

void SimpleDateFormat::addToken(const wchar_t spec,
                                const int repeat,
                                const std::locale& locale,
                                PatternTokenList& pattern) {
    switch(spec) {
      case L'G':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::EraToken(repeat, locale));
      break;

      case L'y':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::YearToken(repeat));
      break;

      case L'M':
      if (repeat <= 2) {
         pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::MonthToken(repeat));
      } else if (repeat <= 3) {
        pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::AbbreviatedMonthNameToken(repeat, locale));
      } else {
        pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::FullMonthNameToken(repeat, locale));
      }
      break;

      case L'w':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::WeekInYearToken(repeat));
      break;

      case L'W':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::WeekInMonthToken(repeat));
      break;

      case L'D':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::DayInYearToken(repeat));
      break;

      case L'd':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::DayInMonthToken(repeat));
      break;

      case L'F':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::DayOfWeekInMonthToken(repeat));
      break;

      case L'E':
      if (repeat <= 3) {
        pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::AbbreviatedDayNameToken(repeat, locale));
      } else {
        pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::FullDayNameToken(repeat, locale));
      }
      break;

      case L'a':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::AMPMToken(repeat, locale));
      break;

      case L'H':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::MilitaryHourToken(repeat, 0));
      break;

      case L'k':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::MilitaryHourToken(repeat, 1));
      break;

      case L'K':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::HourToken(repeat, 0));
      break;

      case L'h':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::HourToken(repeat, 1));
      break;

      case L'm':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::MinuteToken(repeat));
      break;

      case L's':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::SecondToken(repeat));
      break;

      case L'S':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::MillisecondToken(repeat));
      break;

      case L'z':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::GeneralTimeZoneToken(repeat));
      break;

      case L'Z':
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::RFC822TimeZoneToken(repeat));
      break;

      default:
      pattern.push_back(new log4cxx::helpers::SimpleDateFormatImpl::LiteralToken(spec, repeat));
    }
}

void SimpleDateFormat::parsePattern(const LogString& fmt,
      const std::locale& locale,
      PatternTokenList& pattern) {
     if (!fmt.empty()) {
        LogString::const_iterator iter = fmt.begin();
        int repeat = 1;
        wchar_t prevChar = *iter;
        for(iter++; iter != fmt.end(); iter++) {
          if (*iter == prevChar) {
            repeat++;
          } else {
            addToken(prevChar, repeat, locale, pattern);
            prevChar = *iter;
            repeat = 1;
          }
        }
        addToken(prevChar, repeat, locale, pattern);
     }
}

void SimpleDateFormat::format(LogString& s, log4cxx_time_t time, Pool& p) const  {
  apr_time_exp_t exploded;
  apr_status_t stat = timeZone->explode(&exploded, time);
  if (stat == APR_SUCCESS) {
    std::wstring formatted;
    for(PatternTokenList::const_iterator iter = pattern.begin();
        iter != pattern.end();
        iter++) {
        (*iter)->format(formatted, exploded, p);
    }
    log4cxx::helpers::Transcoder::decode(formatted, s);
  }
}

void SimpleDateFormat::setTimeZone(const TimeZonePtr& zone) {
  timeZone = zone;
}


