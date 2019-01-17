//OpenSslExecutable.cpp by Emercoin developers
#include "OpenSslExecutable.h"
#include "OpenSslConfigWriter.h"
#include "Settings.h"
#include "CertLogger.h"
#include <QCoreApplication>
#include <QLineEdit>
#include <QDialog>
#include <QFormLayout>
#include <QLabel>
#include <QFileInfo>
#include <QDir>
#include <QTimer>
#include <QCompleter>
#include <QDirModel>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QThread>

extern "C"
int chdir(const char *filename);
void OpenSslExecutable::setWorkingDirectory(const QString & s) {
	_dir = s;
	chdir(_args(s));
}
QString OpenSslExecutable::workingDirectory()const {
	return _dir;
}
OpenSslExecutable::OpenSslExecutable() {
	setWorkingDirectory(Settings::certDir().absolutePath());
}
bool OpenSslExecutable::existsOrExit(const QDir & dir, const QString & file) {
	if(dir.exists(file))
		return true;
	_strOutput += tr("File %1 does not exist").arg(file);
	return false;
}
QString OpenSslExecutable::cfgFilePath() {
	 return OpenSslConfigWriter::configPath();
}
bool OpenSslExecutable::deleteOrExit(QDir & dir, const QString & file, int tries) {
	for(int i = 0; i<tries; ++i) {
		if(i>0)
			QThread::msleep(50);
		dir.remove(file);
		if(!dir.exists(file))
			return true;
	}
	_strOutput += tr("File %1 can't be removed").arg(file);
	return false;
}

extern "C" int req_main(char* stemplate,
	char* keyout,
	char* subj,
	char* outfile);
bool OpenSslExecutable::generateKeyAndCertificateRequest(const QString & baseName, const QString & subj_) {
	log(tr("Generate key and certificate request:"));
	QDir dir = workingDirectory();
	const QString keyFile = dir.absoluteFilePath(baseName + ".key");
	const QString csrFile = dir.absoluteFilePath(baseName + ".csr");
	if(!deleteOrExit(dir, keyFile))
		return false;
	if(!deleteOrExit(dir, csrFile))
		return false;
	log(QString("simulate call: openssl req -config %1 -new -newkey rsa:2048 -nodes -keyout %2 -subj %3 -out %4")
		.arg(cfgFilePath(), keyFile, subj_, csrFile));
	int code = req_main(_args(cfgFilePath()),
						_args(keyFile),
						_args(subj_),
						_args(csrFile));
	if(code) {
		log(tr("Error - openssl req returned %1").arg(code));
		return false;
	}
	return existsOrExit(dir, keyFile) && existsOrExit(dir, csrFile);
}
extern "C"
int ca_main(char *configfile, const char *infile, const char* outfile);
bool OpenSslExecutable::generateCertificate(const QString & baseName, const QString & configDir) {
	log(tr("Generate certificate:"));
	QDir dir = workingDirectory();
	const QString csrFile = dir.absoluteFilePath(baseName + ".csr");
	const QString crtFile = dir.absoluteFilePath(baseName + ".crt");
	if(!existsOrExit(dir, csrFile))
		return false;
	if(!deleteOrExit(dir, crtFile))
		return false;
	log(QString("simulate call: openssl ca -config %1 -in %2 -out %3 -batch")
		.arg(configDir + "/ca.config", csrFile, crtFile));
	chdir(_args(Settings::certDir().absolutePath()));
	int code = ca_main(_args(configDir + "/ca.config"), _args(csrFile), _args(crtFile));
	if(code) {
		log(tr("Error - openssl ca returned %1").arg(code));
		return false;
	}
	return existsOrExit(dir, crtFile);
}
static const QString passKeyName = "b20bdb78a28343488aace4fc75dd47cf";
extern "C"
int pkcs12_export(
		const char* infile,// -in
		const char* keyname,//-inKey
		const char* certfile,//-certfile
		const char* outfile,//-out
		const char* passoutarg//-passout
		);
bool OpenSslExecutable::createCertificatePair(const QString & baseName, const QString & configDir, const QString & pass) {
	log(tr("Create certificate pair:"));
	QDir dir = workingDirectory();
	const QString keyFile = dir.absoluteFilePath(baseName + ".key");
	const QString crtFile = dir.absoluteFilePath(baseName + ".crt");
	const QString p12 = dir.absoluteFilePath(baseName + ".p12");
	if(!existsOrExit(dir, keyFile))
		return false;
	if(!existsOrExit(dir, crtFile))
		return false;
	dir.remove(p12);
	log("simulate call: openssl pkcs12 -export -in $CRT -inkey $KEY -certfile $CA_DIR/emcssl_ca.crt -out $P12 -passout env:xxx");
	int code = pkcs12_export(
				_args(crtFile),
				_args(keyFile),
				_args(configDir + "/emcssl_ca.crt"),
				_args(p12),
				_args(pass));
	if(code) {
		log(tr("Error - openssl pkcs12 returned %1").arg(code));
		return false;
	}
	return existsOrExit(dir, p12);
}
QString OpenSslExecutable::log(const QString & s) {
	if(_logger) {
		_logger->append(s);
	}
	return s;
}
void OpenSslExecutable::setLogger(CertLogger*l) {
	_logger = l;
}
extern "C"
int enc_main(const char *infile, const char*alg, char*pass, char*outfile);
bool OpenSslExecutable::encryptInfocardAes(const QString& fileIn, const QString & outFile, const QString & pass) {
	log(QString("simulate call: openssl enc -aes-256-cbc -salt -out $OUTF -pass ..."));
	int code = enc_main(_args(fileIn), "aes-256-cbc", _args(pass), _args(outFile));
	if(code) {
		log(tr("Error - openssl pkcs12 returned %1").arg(code));
		return false;
	}
	return true;
}
