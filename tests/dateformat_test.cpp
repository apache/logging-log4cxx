#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/absolutetimedateformat.h>
#include <log4cxx/helpers/iso8601dateformat.h>
#include <log4cxx/helpers/datetimedateformat.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

int main()
{
	int ret = EXIT_SUCCESS;

	try
	{
		// 1973-06-27 12:15:08,012 GMT
		::putenv("TZ=GMT");
		tm tmTest = { 8, 15, 12, 27, 5, 73, 0, 0, 0 };
		int64_t date = ((int64_t)mktime(&tmTest) * 1000) + 12;

		StringBuffer sbuf;

		AbsoluteTimeDateFormat abs("GMT");
		abs.format(sbuf, date);
		if (sbuf.str() != _T("12:15:08"))
		{
			tcout << sbuf.str() << std::endl;
			ret = EXIT_FAILURE;
		}

		ISO8601DateFormat iso("GMT");
		sbuf.str(_T(""));
		iso.format(sbuf, date);
		String result = sbuf.str();
		if (sbuf.str() != _T("1973-06-27 12:15:08,012"))
		{
			tcout << sbuf.str() << std::endl;
			ret = EXIT_FAILURE;
		}

		DateTimeDateFormat datetime("GMT");
		sbuf.str(_T(""));
		datetime.format(sbuf, date);
		if (sbuf.str() != _T("27 Jun 1973 12:15:08"))
		{
			tcout << sbuf.str() << std::endl;
			ret = EXIT_FAILURE;
		}
	}
	catch(Exception&)
	{
		ret = EXIT_FAILURE;
	}

	return ret;
}
