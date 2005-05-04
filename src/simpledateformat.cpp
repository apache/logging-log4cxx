/* * Copyright 2003,2005 The Apache Software Foundation. * * Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License. * You may obtain a copy of the License at *
*      http://www.apache.org/licenses/LICENSE-2.0 * * Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and * limitations under the License. */

#include <log4cxx/helpers/simpledateformat.h>

#include <apr_time.h>
#include <apr_strings.h>
#include <sstream>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/stringhelper.h>
#include <assert.h>
#include <log4cxx/private/log4cxx.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

using namespace std;

#if LOG4CXX_HAS_STD_LOCALE
  #include <locale>
#endif

#if LOG4CXX_HAS_STD_WLOCALE && LOG4CXX_HAS_WCHAR_T
typedef wchar_t localechar;
    #define LOG4CXX_LOCALE_STR(str) L ## str
  #else
typedef char localechar;
    #define LOG4CXX_LOCALE_STR(str) str
#endif



SimpleDateFormat::PatternToken::PatternToken()
{
}

SimpleDateFormat::PatternToken::~PatternToken()
{
}

void SimpleDateFormat::PatternToken::setTimeZone( const TimeZonePtr & zone )
{
}




namespace log4cxx
{
  namespace helpers
  {
    namespace SimpleDateFormatImpl
    {




#if LOG4CXX_HAS_STD_LOCALE
      void renderFacet( const std::locale & locale, std::basic_ostream < localechar > & buffer, const tm * time,
           const localechar spec )
           {

       #if defined(_USEFAC)
             _USEFAC( locale, std::time_put < localechar > ).put( buffer, buffer, time, spec );
       #else
             std::use_facet < std::time_put < localechar > > ( locale ).put( buffer, buffer, buffer.fill(), time, spec );
       #endif

      }
#endif


      void renderFacet( LogString & result, apr_time_exp_t * tm, const char * format )
      {
        enum
        {
          BUFSIZE = 256
        };
        char buf[BUFSIZE];
        apr_size_t retsize;
        apr_status_t stat = apr_strftime( buf, & retsize, BUFSIZE, format, tm );
        if ( stat != APR_SUCCESS )
        {
          buf[0] = '?';
          retsize = 1;
        }
        Transcoder::decode( buf, retsize, result );
      }

    }
  }
}

using namespace log4cxx::helpers::SimpleDateFormatImpl;



class LiteralToken : public SimpleDateFormat::PatternToken
{
public:
  LiteralToken( localechar ch, int count ) : ch( ch ), count( count )
  {
  }

  void format( std::basic_string < localechar > & s, const apr_time_exp_t & tm, Pool & p ) const
  {
    s.append( count, ch );
  }

private:
  localechar ch;
  int count;
};



class EraToken : public SimpleDateFormat::PatternToken
{
public:
  EraToken( int count, const std::locale * locale )
  {
  }

  void format( std::basic_string < localechar > & s, const apr_time_exp_t & tm, Pool & p ) const
  {
    s.append( LOG4CXX_LOCALE_STR( "AD" ) );
  }
};



class NumericToken : public SimpleDateFormat::PatternToken
{
public:
  NumericToken( size_t width ) : width( width )
  {
  }

  virtual int getField( const apr_time_exp_t & tm ) const = 0;

  void format( std::basic_string < localechar > & s, const apr_time_exp_t & tm, Pool & p ) const
  {
    size_t initialLength = s.length();
    StringHelper::toString( getField( tm ), p, s );
    size_t finalLength = s.length();
    if ( initialLength + width > finalLength )
    {
      s.insert( initialLength, ( initialLength + width ) - finalLength, LOG4CXX_LOCALE_STR( '0' ) );
    }
  }

private:
  size_t width;
  char zeroDigit;
};



class YearToken : public NumericToken
{
public:
  YearToken( int width ) : NumericToken( width )
  {
  }

  int getField( const apr_time_exp_t & tm ) const
  {
    return 1900 + tm.tm_year;
  }
};



class MonthToken : public NumericToken
{
public:
  MonthToken( int width ) : NumericToken( width )
  {
  }

  int getField( const apr_time_exp_t & tm ) const
  {
    return tm.tm_mon + 1;
  }
};



class AbbreviatedMonthNameToken : public SimpleDateFormat::PatternToken
{
public:
  AbbreviatedMonthNameToken( int width, const std::locale * locale ) : names( 12 )
  {
#if LOG4CXX_HAS_STD_LOCALE
    if ( locale != NULL )
    {
      tm time;
      memset( & time, sizeof( time ), 0 );
      std::basic_ostringstream < localechar > buffer;
      size_t start = 0;
      for ( int imon = 0; imon < 12; imon++ )
      {
        time.tm_mon = imon;
        renderFacet( * locale, buffer, & time, LOG4CXX_LOCALE_STR( 'b' ) );
        std::basic_string < localechar > monthnames( buffer.str() );
        names[imon] = monthnames.substr( start );
        start = monthnames.length();
      }
      return;
    }
#endif
    apr_time_exp_t time;
    memset( & time, sizeof( time ), 0 );
    for ( int imon = 0; imon < 12; imon++ )
    {
      time.tm_mon = imon;
      renderFacet( names[imon], & time, "%b" );
    }
  }

  void format( std::basic_string < localechar > & s, const apr_time_exp_t & tm, Pool & p ) const
  {
    s.append( names[tm.tm_mon] );
  }

private:
  std::vector < std::basic_string < localechar > > names;

};



class FullMonthNameToken : public SimpleDateFormat::PatternToken
{
public:
  FullMonthNameToken( int width, const std::locale * locale ) : names( 12 )
  {
#if LOG4CXX_HAS_STD_LOCALE
    if ( locale != NULL )
    {
      tm time;
      memset( & time, sizeof( time ), 0 );
      std::basic_ostringstream < localechar > buffer;
      size_t start = 0;
      for ( int imon = 0; imon < 12; imon++ )
      {
        time.tm_mon = imon;
        renderFacet( * locale, buffer, & time, LOG4CXX_LOCALE_STR( 'B' ) );
        std::basic_string < localechar > monthnames( buffer.str() );
        names[imon] = monthnames.substr( start );
        start = monthnames.length();
      }
      return;
    }
#endif
    apr_time_exp_t time;
    memset( & time, sizeof( time ), 0 );
    for ( int imon = 0; imon < 12; imon++ )
    {
      time.tm_mon = imon;
      renderFacet( names[imon], & time, "%B" );
    }
  }

  void format( std::basic_string < localechar > & s, const apr_time_exp_t & tm, Pool & p ) const
  {
    s.append( names[tm.tm_mon] );
  }

private:
  std::vector < std::basic_string < localechar > > names;

};



class WeekInYearToken : public NumericToken
{
public:
  WeekInYearToken( int width ) : NumericToken( width )
  {
  }

  int getField( const apr_time_exp_t & tm ) const
  {
    return tm.tm_yday / 7;
  }
};



class WeekInMonthToken : public NumericToken
{
public:
  WeekInMonthToken( int width ) : NumericToken( width )
  {
  }

  int getField( const apr_time_exp_t & tm ) const
  {
    return tm.tm_mday / 7;
  }
};



class DayInMonthToken : public NumericToken
{
public:
  DayInMonthToken( int width ) : NumericToken( width )
  {
  }

  int getField( const apr_time_exp_t & tm ) const
  {
    return tm.tm_mday;
  }
};



class DayInYearToken : public NumericToken
{
public:
  DayInYearToken( int width ) : NumericToken( width )
  {
  }

  int getField( const apr_time_exp_t & tm ) const
  {
    return tm.tm_yday;
  }
};



class DayOfWeekInMonthToken : public NumericToken
{
public:
  DayOfWeekInMonthToken( int width ) : NumericToken( width )
  {
  }

  int getField( const apr_time_exp_t & tm ) const
  {
    return -1;
  }
};



class AbbreviatedDayNameToken : public SimpleDateFormat::PatternToken
{
public:
  AbbreviatedDayNameToken( int width, const std::locale * locale ) : names( 7 )
  {
#if LOG4CXX_HAS_STD_LOCALE
    if ( locale != NULL )
    {
      tm time;
      memset( & time, sizeof( time ), 0 );
      std::basic_ostringstream < localechar > buffer;
      size_t start = 0;
      for ( int iday = 0; iday < 7; iday++ )
      {
        time.tm_wday = iday;
        renderFacet( * locale, buffer, & time, LOG4CXX_LOCALE_STR( 'a' ) );
        std::basic_string < localechar > daynames( buffer.str() );
        names[iday] = daynames.substr( start );
        start = daynames.length();
      }
      return;
    }
#endif
    apr_time_exp_t time;
    memset( & time, sizeof( time ), 0 );
    for ( int iday = 0; iday < 7; iday++ )
    {
      time.tm_wday = iday;
      renderFacet( names[iday], & time, "%a" );
    }
  }

  void format( std::basic_string < localechar > & s, const apr_time_exp_t & tm, Pool & p ) const
  {
    s.append( names[tm.tm_wday] );
  }

private:
  std::vector < std::basic_string < localechar > > names;

};



class FullDayNameToken : public SimpleDateFormat::PatternToken
{
public:
  FullDayNameToken( int width, const std::locale * locale ) : names( 7 )
  {
#if LOG4CXX_HAS_STD_LOCALE
    if ( locale != NULL )
    {
      tm time;
      memset( & time, sizeof( time ), 0 );
      std::basic_ostringstream < localechar > buffer;
      size_t start = 0;
      for ( int iday = 0; iday < 7; iday++ )
      {
        time.tm_wday = iday;
        renderFacet( * locale, buffer, & time, LOG4CXX_LOCALE_STR( 'A' ) );
        std::basic_string < localechar > daynames( buffer.str() );
        names[iday] = daynames.substr( start );
        start = daynames.length();
      }
      return;
    }
#endif
    apr_time_exp_t time;
    memset( & time, sizeof( time ), 0 );
    for ( int iday = 0; iday < 7; iday++ )
    {
      time.tm_wday = iday;
      renderFacet( names[iday], & time, "%A" );
    }
  }

  void format( std::basic_string < localechar > & s, const apr_time_exp_t & tm, Pool & p ) const
  {
    s.append( names[tm.tm_wday] );
  }

private:
  std::vector < std::basic_string < localechar > > names;

};



class MilitaryHourToken : public NumericToken
{
public:
  MilitaryHourToken( int width, int offset ) : NumericToken( width ), offset( offset )
  {
  }

  int getField( const apr_time_exp_t & tm ) const
  {
    return tm.tm_hour + offset;
  }

private:
  int offset;
};



class HourToken : public NumericToken
{
public:
  HourToken( int width, int offset ) : NumericToken( width )
  {
  }

  int getField( const apr_time_exp_t & tm ) const
  {
    return ( ( tm.tm_hour + 12 - offset ) % 12 ) + offset;
  }

private:
  int offset;
};



class MinuteToken : public NumericToken
{
public:
  MinuteToken( int width ) : NumericToken( width )
  {
  }

  int getField( const apr_time_exp_t & tm ) const
  {
    return tm.tm_min;
  }
};



class SecondToken : public NumericToken
{
public:
  SecondToken( int width ) : NumericToken( width )
  {
  }

  int getField( const apr_time_exp_t & tm ) const
  {
    return tm.tm_sec;
  }
};



class MillisecondToken : public NumericToken
{
public:
  MillisecondToken( int width ) : NumericToken( width )
  {
  }

  int getField( const apr_time_exp_t & tm ) const
  {
    return tm.tm_usec / 1000;
  }
};



class AMPMToken : public SimpleDateFormat::PatternToken
{
public:
  AMPMToken( int width, const std::locale * locale ) : names( 2 )
  {
#if LOG4CXX_HAS_STD_LOCALE
    if ( locale != NULL )
    {
      tm time;
      memset( & time, sizeof( time ), 0 );
      std::basic_ostringstream < localechar > buffer;
      size_t start = 0;
      for ( int i = 0; i < 2; i++ )
      {
        time.tm_hour = i * 12;
        renderFacet( * locale, buffer, & time, LOG4CXX_LOCALE_STR( 'p' ) );
        std::basic_string < localechar > ampm = buffer.str();
        names[i] = ampm.substr( start );
        start = ampm.length();
      }
      return;
    }
#endif
    apr_time_exp_t time;
    memset( & time, sizeof( time ), 0 );
    for ( int i = 0; i < 2; i++ )
    {
      time.tm_hour = i * 12;
      renderFacet( names[i], & time, "%p" );
    }
  }

  void format( std::basic_string < localechar > & s, const apr_time_exp_t & tm, Pool & p ) const
  {
    s.append( names[tm.tm_hour / 12] );
  }

private:
  std::vector < std::basic_string < localechar > > names;
};



class GeneralTimeZoneToken : public SimpleDateFormat::PatternToken
{
public:
  GeneralTimeZoneToken( int width )
  {
  }

  void format( std::basic_string < localechar > & s, const apr_time_exp_t & tm, Pool & p ) const
  {
    std::basic_string < localechar > tzID;
    Transcoder::encode( timeZone->getID(), tzID );
    s.append( tzID );
  }

  void setTimeZone( const TimeZonePtr & zone )
  {
    timeZone = zone;
  }

private:
  TimeZonePtr timeZone;
};



class RFC822TimeZoneToken : public SimpleDateFormat::PatternToken
{
public:
  RFC822TimeZoneToken( int width )
  {
  }

  void format( std::basic_string < localechar > & s, const apr_time_exp_t & tm, Pool & p ) const
  {
    if ( tm.tm_gmtoff == 0 )
    {
      s.append( 1, LOG4CXX_LOCALE_STR( 'Z' ) );
    }
    else
    {
      apr_int32_t off = tm.tm_gmtoff;
      size_t basePos = s.length();
      s.append( LOG4CXX_LOCALE_STR( "+0000" ) );
      if ( off < 0 )
      {
        s[basePos] = LOG4CXX_LOCALE_STR( '-' );
        off = -off;
      }
      std::basic_string < localechar > hours;
      StringHelper::toString( off / 3600, p, hours );
      size_t hourPos = basePos + 2;
      //
      //   assumes that point values for 0-9 are same between char and wchar_t
      //
      for ( size_t i = hours.length(); i-- > 0; )
      {
        s[hourPos--] = hours[i];
      }
      std::basic_string < localechar > min;
      StringHelper::toString( ( off % 3600 ) / 60, p, min );
      size_t minPos = basePos + 4;
      //
      //   assumes that point values for 0-9 are same between char and wchar_t
      //
      for ( size_t j = min.length(); j-- > 0; )
      {
        s[minPos--] = min[j];
      }
    }
  }
};




namespace log4cxx
{
  namespace helpers
  {
    namespace SimpleDateFormatImpl
    {


      void addToken( const localechar spec, const int repeat, const std::locale * locale,
           std::vector < SimpleDateFormat::PatternToken * > & pattern )
           {
             SimpleDateFormat::PatternToken * token = NULL;
             switch ( spec )
             {
               case LOG4CXX_LOCALE_STR( 'G' ):
                 token = ( new EraToken( repeat, locale ) );
               break;

               case LOG4CXX_LOCALE_STR( 'y' ):
                 token = ( new YearToken( repeat ) );
               break;

               case LOG4CXX_LOCALE_STR( 'M' ):
                 if ( repeat <= 2 )
                 {
                   token = ( new MonthToken( repeat ) );
                 }
                 else if ( repeat <= 3 )
                 {
                   token = ( new AbbreviatedMonthNameToken( repeat, locale ) );
                 }
                 else
                 {
                   token = ( new FullMonthNameToken( repeat, locale ) );
                 }
               break;

               case LOG4CXX_LOCALE_STR( 'w' ):
                 token = ( new WeekInYearToken( repeat ) );
               break;

               case LOG4CXX_LOCALE_STR( 'W' ):
                 token = ( new WeekInMonthToken( repeat ) );
               break;

               case LOG4CXX_LOCALE_STR( 'D' ):
                 token = ( new DayInYearToken( repeat ) );
               break;

               case LOG4CXX_LOCALE_STR( 'd' ):
                 token = ( new DayInMonthToken( repeat ) );
               break;

               case LOG4CXX_LOCALE_STR( 'F' ):
                 token = ( new DayOfWeekInMonthToken( repeat ) );
               break;

               case LOG4CXX_LOCALE_STR( 'E' ):
                 if ( repeat <= 3 )
                 {
                   token = ( new AbbreviatedDayNameToken( repeat, locale ) );
                 }
                 else
                 {
                   token = ( new FullDayNameToken( repeat, locale ) );
                 }
               break;

               case LOG4CXX_LOCALE_STR( 'a' ):
                 token = ( new AMPMToken( repeat, locale ) );
               break;

               case LOG4CXX_LOCALE_STR( 'H' ):
                 token = ( new MilitaryHourToken( repeat, 0 ) );
               break;

               case LOG4CXX_LOCALE_STR( 'k' ):
                 token = ( new MilitaryHourToken( repeat, 1 ) );
               break;

               case LOG4CXX_LOCALE_STR( 'K' ):
                 token = ( new HourToken( repeat, 0 ) );
               break;

               case LOG4CXX_LOCALE_STR( 'h' ):
                 token = ( new HourToken( repeat, 1 ) );
               break;

               case LOG4CXX_LOCALE_STR( 'm' ):
                 token = ( new MinuteToken( repeat ) );
               break;

               case LOG4CXX_LOCALE_STR( 's' ):
                 token = ( new SecondToken( repeat ) );
               break;

               case LOG4CXX_LOCALE_STR( 'S' ):
                 token = ( new MillisecondToken( repeat ) );
               break;

               case LOG4CXX_LOCALE_STR( 'z' ):
                 token = ( new GeneralTimeZoneToken( repeat ) );
               break;

               case LOG4CXX_LOCALE_STR( 'Z' ):
                 token = ( new RFC822TimeZoneToken( repeat ) );
               break;

               default:
                 token = ( new LiteralToken( spec, repeat ) );
             }
             assert( token != NULL );
             pattern.push_back( token );
      }

      void parsePattern( const LogString & fmt, const std::locale * locale,
           std::vector < SimpleDateFormat::PatternToken * > & pattern )
           {
             if ( !fmt.empty() )
             {
               LogString::const_iterator iter = fmt.begin();
               int repeat = 1;
               localechar prevChar = * iter;
               for ( iter++; iter != fmt.end(); iter++ )
               {
                 if ( * iter == prevChar )
                 {
                   repeat++;
                 }
                 else
                 {
                   addToken( prevChar, repeat, locale, pattern );
                   prevChar = * iter;
                   repeat = 1;
                 }
               }
               addToken( prevChar, repeat, locale, pattern );
             }
      }
    }
  }
}




SimpleDateFormat::SimpleDateFormat( const LogString & fmt ) : timeZone( TimeZone::getDefault() )
{
#if LOG4CXX_HAS_STD_LOCALE
  std::locale defaultLocale;
  parsePattern( fmt, & defaultLocale, pattern );
#else
  parsePattern( fmt, NULL, pattern );
#endif
  for ( PatternTokenList::iterator iter = pattern.begin(); iter != pattern.end(); iter++ )
  {
    ( * iter )->setTimeZone( timeZone );
  }
}

SimpleDateFormat::SimpleDateFormat( const LogString & fmt, const std::locale * locale ) : timeZone( TimeZone::getDefault() )
{
  parsePattern( fmt, locale, pattern );
  for ( PatternTokenList::iterator iter = pattern.begin(); iter != pattern.end(); iter++ )
  {
    ( * iter )->setTimeZone( timeZone );
  }
}


SimpleDateFormat::~SimpleDateFormat()
{
  for ( PatternTokenList::iterator iter = pattern.begin(); iter != pattern.end(); iter++ )
  {
    delete * iter;
  }
}


void SimpleDateFormat::format( LogString & s, log4cxx_time_t time, Pool & p ) const
{
  apr_time_exp_t exploded;
  apr_status_t stat = timeZone->explode( & exploded, time );
  if ( stat == APR_SUCCESS )
  {
    std::basic_string < localechar > formatted;
    for ( PatternTokenList::const_iterator iter = pattern.begin(); iter != pattern.end(); iter++ )
    {
      ( * iter )->format( formatted, exploded, p );
    }
    log4cxx::helpers::Transcoder::decode( formatted, s );
  }
}

void SimpleDateFormat::setTimeZone( const TimeZonePtr & zone )
{
  timeZone = zone;
}
