//ConfigFile.h by emercoin developers
#pragma once
#include <QFile>

class ConfigFile: public QFile {
	public:
		ConfigFile();
		static QString path();
		QString load();//return status, empty -> ok
		QString save();

		QStringList _lines;
		const QString _fileName;
		QVariant option(const QString& name)const;
		void setOption(const QString& name, const QString& value);
		void setOption(const QString& name, int n);

		bool server()const;
		bool listen()const;
		QString rpcuser()const;
		QString rpcpassword()const;
		QString debug()const;

		void setServer(bool b);
		void setListen(bool b);
		void setRpcuser(const QString & s);
		void setRpcpassword(const QString & s);
		void setDebug(const QString & s);
};
