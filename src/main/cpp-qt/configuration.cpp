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
#include <log4cxx-qt/configuration.h>
#include <log4cxx-qt/transcoder.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/propertyconfigurator.h>
#include <QFileSystemWatcher>
#include <QDir>
#include <QFile>
#include <memory>
#include <QDebug>

namespace
{
using namespace LOG4CXX_NS;

spi::ConfigurationStatus tryLoadFile(const LogString& lsFilename)
{
	return helpers::StringHelper::endsWith(lsFilename, LOG4CXX_STR(".xml"))
		? xml::DOMConfigurator::configure(lsFilename)
		: PropertyConfigurator::configure(lsFilename);
}

spi::ConfigurationStatus tryLoadFile(const QString& filename)
{
	LOG4CXX_DECODE_QSTRING(lsFilename, filename);
	return tryLoadFile(lsFilename);
}

} // namespace

namespace LOG4CXX_NS::qt
{

void Configuration::reconfigureWhenModified(const QString& filename)
{
	static auto watcher = std::make_unique<QFileSystemWatcher>();
	QFileInfo fi(filename);
	// From the Qt docs:
	// Note that QFileSystemWatcher stops monitoring files once they have been renamed
	// or removed from disk, and directories once they have been removed from disk.
	//
	// Some text editing programs will replace the file with a new one, which deletes
	// the old file(thus causing Qt to remove the watch), so we need to add in the
	// file whenever the directory changes.
	// See also: https://stackoverflow.com/questions/18300376/qt-qfilesystemwatcher-signal-filechanged-gets-emited-only-once
	watcher->addPath(fi.absolutePath());
	if (helpers::LogLog::isDebugEnabled())
	{
		LOG4CXX_DECODE_QSTRING(lsDir, fi.absolutePath());
		helpers::LogLog::debug(LOG4CXX_STR("Watching directory ") + lsDir);
	}
	watcher->addPath(fi.absoluteFilePath());
	if (helpers::LogLog::isDebugEnabled())
	{
		LOG4CXX_DECODE_QSTRING(lsFile, fi.absoluteFilePath());
		helpers::LogLog::debug(LOG4CXX_STR("Watching file ") + lsFile);
	}
	QObject::connect(watcher.get(), &QFileSystemWatcher::directoryChanged
		, [fi](const QString&){
			if (fi.exists())
				watcher->addPath(fi.absoluteFilePath());
		});
	QObject::connect(watcher.get(), &QFileSystemWatcher::fileChanged
		, [](const QString& fullPath){
			tryLoadFile(fullPath);
		});
}

void Configuration::reconfigureWhenModified(const LogString& lsFilename)
{
	LOG4CXX_ENCODE_QSTRING(filename, lsFilename);
	reconfigureWhenModified(filename);
}

	std::tuple<spi::ConfigurationStatus,QString>
Configuration::configureFromFileAndWatch
	( const QVector<QString>& directories
	, const QVector<QString>& filenames
	)
{
	for( QString dir : directories )
	{
		for( QString fname : filenames )
		{
			QString candidate_str = dir + "/" + fname;
			QFile candidate(candidate_str);

			if (helpers::LogLog::isDebugEnabled())
			{
				LOG4CXX_DECODE_QSTRING(msg, "Checking file " + candidate_str);
				helpers::LogLog::debug(msg);
			}
			if (candidate.exists())
			{
				auto configStatus = tryLoadFile(candidate_str);
				if( configStatus == spi::ConfigurationStatus::Configured )
				{
					reconfigureWhenModified(candidate_str);
					return {configStatus, candidate_str};
				}
				if (helpers::LogLog::isDebugEnabled())
				{
					LOG4CXX_DECODE_QSTRING(failmsg, "Unable to load  " + candidate_str + ": trying next");
					helpers::LogLog::debug(failmsg);
				}
			}
		}
	}

	return {spi::ConfigurationStatus::NotConfigured, QString()};
}

} // namespace LOG4CXX_NS::qt
