#pragma once
#include <qobject.h>
class TlsError :
    public QObject
{
    Q_OBJECT

public:
    TlsError(QObject* parent = 0);

    // Executes the dialog and shows the given error message
    void exec(const QString& message);

    // The accessor methods of the properties
    bool visible() const;
    QString message() const;

public Q_SLOTS:
    // This method is invoked from the UI if the user wants to ignore the SSL errors
    void ignore();

    // This method is invoked from the UI if the user wants to cancel the connection
    void cancel();

    // This method is invoked from the UI if the user wants to view the certificate chain
    void viewCertificateChain();

Q_SIGNALS:
    // The change notification signals of the properties
    void visibleChanged();
    void messageChanged();

    // This signal is emitted when the user wants to ignore the SSL errors
    void ignoreSslErrors();

    // This signal is emitted when the user wants to view the certificate chain
    void viewCertificateChainRequested();

private:
    
    // The property values
    bool m_ignoreSslErrors;
    bool m_visible;
    QString m_message;
};

