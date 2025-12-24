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
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/propertyconfigurator.h>

#include <QFileSystemWatcher>
#include <QDir>
#include <QFile>
#include <memory>
#include <QDebug>

namespace LOG4CXX_NS
{
namespace qt
{
using helpers::LogLog;

static std::unique_ptr<QFileSystemWatcher> watcher;
static QString configFilename;

static void loadXMLFile(const QString& path){
	QFileInfo fi(configFilename);
	if(!fi.exists()){
		return;
	}
	LOG4CXX_DECODE_QSTRING(lsPath, path);
	xml::DOMConfigurator::configure(path.toStdString());
}

static void loadPropertiesFile(const QString& path){
	QFileInfo fi(configFilename);
	if(!fi.exists()){
		return;
	}
	LOG4CXX_DECODE_QSTRING(lsPath, path);
	PropertyConfigurator::configure(lsPath);
}

static void dirChanged(const QString&){
	QFileInfo fi(configFilename);
	if(fi.exists()){
		// From the Qt docs:
		// Note that QFileSystemWatcher stops monitoring files once they have been renamed
		// or removed from disk, and directories once they have been removed from disk.
		//
		// Some text editing programs will replace the file with a new one, which deletes
		// the old file(thus causing Qt to remove the watch), so we need to add in the
		// file whenever the directory changes.
		// See also: https://stackoverflow.com/questions/18300376/qt-qfilesystemwatcher-signal-filechanged-gets-emited-only-once
		watcher->addPath(configFilename);
	}
}

Configuration::Configuration(){}

spi::ConfigurationStatus Configuration::tryLoadFile(const QString& filename){
	auto stat = spi:: ConfigurationStatus::NotConfigured;
	auto isXML = false;

	LOG4CXX_DECODE_QSTRING(lsFilename, filename);
	if(filename.endsWith(".xml")){
		stat = xml::DOMConfigurator::configure(lsFilename);
		isXML = true;
	}else if(filename.endsWith(".properties")){
		stat = PropertyConfigurator::configure(lsFilename);
	}

	if( stat == spi::ConfigurationStatus::Configured ){
		watcher = std::make_unique<QFileSystemWatcher>();
		configFilename = filename;
		QFileInfo fi(filename);
		watcher->addPath(fi.dir().absolutePath());
		watcher->addPath(filename);

		QObject::connect(watcher.get(), &QFileSystemWatcher::directoryChanged,
						 &dirChanged);
		if(isXML){
			QObject::connect(watcher.get(), &QFileSystemWatcher::fileChanged,
							 &loadXMLFile);
		}else{
			QObject::connect(watcher.get(), &QFileSystemWatcher::fileChanged,
							 &loadPropertiesFile);
		}
	}

	return stat;
}

std::tuple<spi::ConfigurationStatus,QString>
Configuration::configureFromFileAndWatch(const QVector<QString>& directories,
										 const QVector<QString>& filenames){
	for( QString dir : directories ){
		for( QString fname : filenames ){
			QString candidate_str = dir + "/" + fname;
			QFile candidate(candidate_str);

			if (LogLog::isDebugEnabled())
			{
				LOG4CXX_DECODE_QSTRING(msg, "Checking file " + candidate_str);
				LogLog::debug(msg);
			}
			if (candidate.exists())
			{
				auto configStatus = tryLoadFile(candidate_str);
				if( configStatus == spi::ConfigurationStatus::Configured ){
					return {configStatus, candidate_str};
				}
				if (LogLog::isDebugEnabled())
				{
					LOG4CXX_DECODE_QSTRING(failmsg, "Unable to load  " + candidate_str + ": trying next");
					LogLog::debug(failmsg);
				}
			}
		}
	}

	return {spi::ConfigurationStatus::NotConfigured, QString()};
}

} //namespace helpers
} //namespace log4cxx
