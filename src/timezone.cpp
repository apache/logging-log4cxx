/* * Copyright 2003,2004 The Apache Software Foundation. * * Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License. * You may obtain a copy of the License at *
*      http://www.apache.org/licenses/LICENSE-2.0 * * Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and * limitations under the License. */

#include <log4cxx/helpers/timezone.h>
#include <stdlib.h>
#include <apr-1/apr_time.h>
#include <apr-1/apr_pools.h>
#include <apr-1/apr_strings.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT( TimeZone )

namespace log4cxx
{
  namespace helpers
  {
    namespace TimeZoneImpl
    {
      /** Time zone object that represents GMT. */
      class GMTTimeZone : public TimeZone
      {
      public:
        /** Class factory. */
        static const TimeZonePtr & getInstance()
        {
          static TimeZonePtr tz( new GMTTimeZone() );
          return tz;
        }

        /** Explode time to human readable form. */
        apr_status_t explode( apr_time_exp_t * result, apr_time_t input ) const
        {
          return apr_time_exp_gmt( result, input );
        }

      private:
        GMTTimeZone() : TimeZone( "GMT" )
        {
        }
      };



      /** Time zone object that represents GMT. */
      class LocalTimeZone : public TimeZone
      {
      public:
        /** Class factory. */
        static const TimeZonePtr & getInstance()
        {
          static TimeZonePtr tz( new LocalTimeZone() );
          return tz;
        }

        /** Explode time to human readable form. */
        apr_status_t explode( apr_time_exp_t * result, apr_time_t input ) const
        {
          return apr_time_exp_lt( result, input );
        }


      private:
        LocalTimeZone() : TimeZone( getTimeZoneName() )
        {
        }

        static const String getTimeZoneName()
        {
          const int MAX_TZ_LENGTH = 255;
          char tzName[MAX_TZ_LENGTH];
          apr_size_t tzLength;
          apr_time_exp_t tm;
          apr_time_exp_lt(&tm, 0);
          apr_strftime(tzName, &tzLength, MAX_TZ_LENGTH, "%Z", &tm);
          tzName[tzLength] = 0;
          return tzName;
        }

      };



      /** Time zone object that represents a fixed offset from GMT. */
      class FixedTimeZone : public TimeZone
      {
      public:
        FixedTimeZone( const String & name, apr_int32_t offset ) : TimeZone( name ), offset( offset )
        {
        }

        /** Explode time to human readable form. */
        apr_status_t explode( apr_time_exp_t * result, apr_time_t input ) const
        {
          return apr_time_exp_tz( result, input, offset );
        }


      private:
        const apr_int32_t offset;
      };

    }
  }
}



TimeZone::TimeZone( const String & id ) : id( id )
{
}

TimeZone::~TimeZone()
{
}

const TimeZonePtr & TimeZone::getDefault()
{
  return log4cxx::helpers::TimeZoneImpl::LocalTimeZone::getInstance();
}

const TimeZonePtr & TimeZone::getGMT()
{
  return log4cxx::helpers::TimeZoneImpl::GMTTimeZone::getInstance();
}

const TimeZonePtr TimeZone::getTimeZone( const String & id )
{
  if ( id == "GMT" )
  {
    return log4cxx::helpers::TimeZoneImpl::LocalTimeZone::getInstance();
  }
  if ( id.length() >= 5 && id.substr( 0, 3 ) == "GMT" )
  {
    int hours = 0;
    int minutes = 0;
    int sign = 1;
    if (id[3] == '-') {
      sign = -1;
    }
    std::string off( id.substr( 4 ) );
    if ( id.length() >= 7 )
    {
      int colonPos = off.find( ':' );
      if ( colonPos == String::npos )
      {
        minutes = atoi(off.substr(off.length() - 2).c_str());
        hours = atoi(off.substr(0, off.length() - 2).c_str());
      }
      else
      {
        minutes = atoi(off.substr(colonPos + 1).c_str());
        hours = atoi(off.substr(0, colonPos).c_str());
      }
    } else {
      hours = atoi(off.c_str());
    }
    std::string s("GMT");
    apr_pool_t* p;
    apr_status_t stat = apr_pool_create(&p, NULL);
    char* hh = apr_itoa(p, std::abs(hours));
    if (sign > 0) {
      s.append(1, '+');
    } else {
      s.append(1, '-');
    }
    if (hh[1] == 0) {
      s.append(1, '0');
    }
    s.append(hh);
    s.append(1, ':');
    char* mm = apr_itoa(p, minutes);
    if (mm[1] == 0) {
      s.append(1, '0');
    }
    s.append(mm);
    apr_pool_destroy(p);
    apr_int32_t offset = sign * (hours * 3600 + minutes * 60);
    return new log4cxx::helpers::TimeZoneImpl::FixedTimeZone( s, offset );
  }
  const TimeZonePtr & ltz = getDefault();
  if ( ltz->getID() == id )
  {
    return ltz;
  }
  return getGMT();
}

