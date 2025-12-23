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
#include <log4cxx-qt/messagehandler.h>
#include <log4cxx-qt/transcoder.h>
#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/spi/location/locationinfo.h>

namespace LOG4CXX_NS {
namespace qt {

void messageHandler(QtMsgType type, const QMessageLogContext& context, const QString& message )
{
	spi::LocationInfo location
		( context.file
		, spi::LocationInfo::calcShortFileName(context.file)
		, context.function
		, context.line
		);
	LOG4CXX_DECODE_QSTRING(lsMsg, message);
	auto qtLogger = Logger::getLogger( context.category );
	switch ( type )
	{
		case QtMsgType::QtDebugMsg:
			qtLogger->debug(lsMsg, location);
			break;

		case QtMsgType::QtWarningMsg:
			qtLogger->warn(lsMsg, location);
			break;
#if QT_VERSION >= QT_VERSION_CHECK(5, 5, 0)

		case QtMsgType::QtInfoMsg:
			qtLogger->info(lsMsg, location);
			break;
#endif

		case QtMsgType::QtCriticalMsg:
			qtLogger->error(lsMsg, location);
			break;

		case QtMsgType::QtFatalMsg:
			qtLogger->fatal(lsMsg, location);
			LogManager::shutdown();
			std::abort();
	}
}

} /* namespace qt */
} /* namespace log4cxx */
