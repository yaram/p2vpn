/*
 * This file was generated by qdbusxml2cpp version 0.7
 * Command line was: qdbusxml2cpp -N -p qibusproxy -c QIBusProxy interfaces/org.freedesktop.IBus.xml
 *
 * qdbusxml2cpp is Copyright (C) 2015 The Qt Company Ltd.
 *
 * This is an auto-generated file.
 * Do not edit! All changes made to it will be lost.
 */

#ifndef QIBUSPROXY_H_1308831142
#define QIBUSPROXY_H_1308831142

#include <QObject>
#include <QByteArray>
#include <QList>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QVariant>
#include <QDBusAbstractInterface>
#include <QDBusPendingReply>

#include "qibustypes.h"

/*
 * Proxy class for interface org.freedesktop.IBus
 */
class QIBusProxy: public QDBusAbstractInterface
{
    Q_OBJECT
public:
    static inline const char *staticInterfaceName()
    { return "org.freedesktop.IBus"; }
    static inline QString dbusInterfaceProperties()
    { return QStringLiteral("org.freedesktop.DBus.Properties"); }

public:
    QIBusProxy(const QString &service, const QString &path, const QDBusConnection &connection, QObject *parent = nullptr);

    ~QIBusProxy();

public Q_SLOTS: // METHODS
    inline QDBusPendingReply<QDBusObjectPath> CreateInputContext(const QString &name)
    {
        QList<QVariant> argumentList;
        argumentList << QVariant::fromValue(name);
        return asyncCallWithArgumentList(QLatin1String("CreateInputContext"), argumentList);
    }

    inline QDBusPendingReply<> Exit(bool restart)
    {
        QList<QVariant> argumentList;
        argumentList << QVariant::fromValue(restart);
        return asyncCallWithArgumentList(QLatin1String("Exit"), argumentList);
    }

    inline QDBusPendingReply<QDBusVariant> Ping(const QDBusVariant &data)
    {
        QList<QVariant> argumentList;
        argumentList << QVariant::fromValue(data);
        return asyncCallWithArgumentList(QLatin1String("Ping"), argumentList);
    }

    inline QDBusPendingReply<> RegisterComponent(const QDBusVariant &components)
    {
        QList<QVariant> argumentList;
        argumentList << QVariant::fromValue(components);
        return asyncCallWithArgumentList(QLatin1String("RegisterComponent"), argumentList);
    }

// Property
    inline QDBusPendingCall GetProperty(const QString method)
    {
        if (!this->isValid() || this->service().isEmpty() || this->path().isEmpty())
             return QDBusPendingCall::fromError(this->lastError());

        QDBusMessage msg = QDBusMessage::createMethodCall(this->service(),
                                                          this->path(),
                                                          dbusInterfaceProperties(),
                                                          QStringLiteral("Get"));
        msg << this->interface() << method;
        return this->connection().asyncCall(msg, this->timeout());
    }

#ifdef QIBUS_GET_ADDRESS
    inline QDBusPendingCall Address()
    {
        return GetProperty(QStringLiteral("Address"));
    }
#endif

#ifdef QIBUS_GET_ENGINES
    inline QDBusPendingCall Engines()
    {
        return GetProperty(QStringLiteral("Engines"));
    }
#endif

    inline QDBusPendingCall GlobalEngine()
    {
        return GetProperty(QStringLiteral("GlobalEngine"));
    }

#ifdef QIBUS_GET_ADDRESS
    QString getAddress();
#endif
#ifdef QIBUS_GET_ENGINES
    QList<QIBusEngineDesc> getEngines();
#endif
    QIBusEngineDesc getGlobalEngine();

private:
    void globalEngineChanged(const QString &engine_name);

Q_SIGNALS: // SIGNALS
    void GlobalEngineChanged(const QString &engine_name);
};

#endif
