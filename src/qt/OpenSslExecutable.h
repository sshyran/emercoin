//OpenSslExecutable.h by Emercoin developers
#pragma once
#include <QProcess>
class CertLogger;
class QDir;

class OpenSslExecutable {
	public:
		OpenSslExecutable();
		bool generateKeyAndCertificateRequest(const QString & baseName, const QString & subj);
		bool generateCertificate(const QString & baseName, const QString & configDir);
		bool createCertificatePair(const QString & baseName, const QString & configDir, const QString & pass);
		bool encryptInfocardAes(const QString& fileIn, const QString & outFile, const QString & pass);
		void setLogger(CertLogger*l);
		QString log(const QString & s);
		QString errorString()const { return _strOutput; }
	protected:
		void setWorkingDirectory(const QString & s);
		QString workingDirectory()const;
		QString  _dir;
		QString _strOutput;
		CertLogger* _logger = 0;
		bool existsOrExit(const QDir & dir, const QString & file);
		bool deleteOrExit(QDir & dir, const QString & file, int tries=5);
		void readToMe();
		static QString cfgFilePath();
		struct Args {
			//to call openssl code like it's command line C arguments made from QString
			QList<QByteArray> _strings;
			char* operator()(const QString & s) {
				auto arr = s.toUtf8();
				_strings << arr;
				return _strings.last().data();
			}
		};
		Args _args;
		static QString tr(const char*s) { return QObject::tr(s); }
};
