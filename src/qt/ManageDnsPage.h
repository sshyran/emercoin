//ManageDnsPage.h by emercoin developers
#pragma once
#include <qt/NameValueLineEdits.h>

#include <QDialog>

class QLineEdit;
class QFormLayout;
class QString;
class WalletModel;

class ManageDnsPage: public QDialog {
    public:
        ManageDnsPage(WalletModel* model, QWidget*parent=0);
		QString name()const;
		QString value()const;
    protected:
		NameValueLineEdits* _NVPair = 0;
		QLineEdit* _editName = 0;
		QList<QLineEdit*> _edits;

		void recalcValue();
		QLineEdit* addLineEdit(QFormLayout*form, const QString& dnsParam, const QString& text, const QString& tooltip);
    private:
        WalletModel* model;
};
