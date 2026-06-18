#include "TlsError.h"

TlsError::TlsError(QObject* parent ) {}
void TlsError::exec(const QString& message)
{
}

bool TlsError::visible() const
{
	return false;
}

QString TlsError::message() const
{
	return QString();
}

void TlsError::cancel()
{
}

void TlsError::viewCertificateChain()
{
}
void TlsError::ignore()
{
}
