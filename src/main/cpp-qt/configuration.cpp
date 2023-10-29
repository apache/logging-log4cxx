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
using LOG4CXX_NS::helpers::LogLog;

static std::unique_ptr<QFileSystemWatcher> watcher;
static QString configFilename;

static void loadXMLFile(const QString& path){
	QFileInfo fi(configFilename);
	if(!fi.exists()){
		return;
	}
	LOG4CXX_NS::xml::DOMConfigurator::configure(path.toStdString());
}

static void loadPropertiesFile(const QString& path){
	QFileInfo fi(configFilename);
	if(!fi.exists()){
		return;
	}
	LOG4CXX_NS::PropertyConfigurator::configure(path.toStdString());
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

LOG4CXX_NS::spi::ConfigurationStatus Configuration::tryLoadFile(const QString& filename){
	LOG4CXX_NS::spi::ConfigurationStatus stat =LOG4CXX_NS::spi::ConfigurationStatus::NotConfigured;
	bool isXML = false;

	if(filename.endsWith(".xml")){
		stat = LOG4CXX_NS::xml::DOMConfigurator::configure(filename.toStdString());
		isXML = true;
	}else if(filename.endsWith(".properties")){
		stat = LOG4CXX_NS::PropertyConfigurator::configure(filename.toStdString());
	}

	if( stat == LOG4CXX_NS::spi::ConfigurationStatus::Configured ){
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

std::tuple<LOG4CXX_NS::spi::ConfigurationStatus,QString>
Configuration::configureFromFileAndWatch(const QVector<QString>& directories,
										 const QVector<QString>& filenames){
	for( QString dir : directories ){
		for( QString fname : filenames ){
			QString canidate_str = dir + "/" + fname;
			QFile candidate(canidate_str);

			LOG4CXX_DECODE_QSTRING(msg, "Checking file " + canidate_str);
			LogLog::debug(msg);
			if (candidate.exists())
			{
				LOG4CXX_NS::spi::ConfigurationStatus configStatus = tryLoadFile(canidate_str);
				if( configStatus == LOG4CXX_NS::spi::ConfigurationStatus::Configured ){
					return {configStatus, canidate_str};
				}
				LOG4CXX_DECODE_QSTRING(failmsg, "Unable to load  " + canidate_str + ": trying next");
				LogLog::debug(failmsg);
			}
		}
	}

	return {LOG4CXX_NS::spi::ConfigurationStatus::NotConfigured, QString()};
}

} //namespace helpers
} //namespace log4cxx
