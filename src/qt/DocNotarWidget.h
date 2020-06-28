//DocNotarWidget.h by Emercoin developers
#pragma once
#include <QTabWidget>
#include <QDialog>
class DpoCreateRootWidget;
class DpoCreateRecordWidget;
class DpoRegisterDocWidget;
class WalletModel;

class DocNotarWidget: public QDialog {
	public:
        DocNotarWidget(WalletModel* model, QWidget*parent = nullptr);
		~DocNotarWidget();
		QString name()const;
		QString value()const;
	protected:
		QTabWidget* _tab = 0;

        DpoCreateRootWidget* _createRoot = nullptr;
        DpoCreateRecordWidget* _createRecord = nullptr;
        DpoRegisterDocWidget* _registerDoc = nullptr;
    private:
        WalletModel* model;
};
