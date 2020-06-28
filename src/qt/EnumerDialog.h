//EnumerDialog.h by Emercoin developers
#pragma once
#include <qt/NameValueLineEdits.h>

#include <QSpinBox>

class PhoneNumberLineEdit;
class WalletModel;

class EnumerDialog: public QWidget {
	public:
        EnumerDialog(WalletModel* model);
	protected:
		PhoneNumberLineEdit* _phone = 0;
		QSpinBox* _antiSquatter = new QSpinBox;
		
		NameValueLineEdits* _NVEdit = 0;
		void generateNVPair();
    private:
        WalletModel* model;
};
