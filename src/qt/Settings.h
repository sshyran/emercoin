//Settings.h by Emercoin developers
#pragma once
#include <QDir>

class Settings {
	public:
		static QDir configDir();
		static QString configPath();
		static QDir certDir();
};
