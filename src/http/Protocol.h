/**
 ***************************************************************************
 * @file Response.h
 *
 * @brief
 *
 * Copyright (C) 2013
 *
 * @author	Francois Ferrand
 * @date	4/2013
 ***************************************************************************
 */

#ifndef RESPONSE_H
#define RESPONSE_H

#include <QtCore/QObject>
#include <QtCore/QCryptographicHash>
#include <QtCore/QMetaType>
#include <QtCore/QVariant>
#include <QtCore/QJsonObject>
#include "crypto/SymmetricCipher.h"

namespace KeepassHttpProtocol {

enum RequestType {
    INVALID = -1,
    GET_LOGINS,
    GET_LOGINS_COUNT,
    GET_ALL_LOGINS,
    SET_LOGIN,
    ASSOCIATE,
    TEST_ASSOCIATE,
    GENERATE_PASSWORD
};

//TODO: use QByteArray whenever possible?

class Request
{
public:
    Request();
    bool fromJson(QString text);

    KeepassHttpProtocol::RequestType requestType() const;
    QString requestTypeStr() const;
    bool sortSelection() const;
    QString login() const;
    QString password() const;
    QString uuid() const;
    QString url() const;
    QString submitUrl() const;
    QString key() const;
    QString id() const;
    QString verifier() const;
    QString nonce() const;
    QString realm() const;
    bool CheckVerifier(const QString & key) const;

private:
    QString get(const QString& key) const;

    KeepassHttpProtocol::RequestType m_requestType;
    bool m_sortSelection;
    QString m_key;
    QJsonObject m_jsonObject;
    mutable SymmetricCipher m_cipher;
};

class StringField : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString Key   READ key  )
    Q_PROPERTY(QString Value READ value)

public:
    StringField();
    StringField(const QString& key, const QString& value);
    StringField(const StringField & other);
    StringField &operator =(const StringField &other);

    QString key() const;
    QString value() const;

private:
    QString m_key;
    QString m_value;
};

class Entry : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString Login         READ login          )
    Q_PROPERTY(QString Password      READ password       )
    Q_PROPERTY(QString Uuid          READ uuid           )
    Q_PROPERTY(QString Name          READ name           )
    Q_PROPERTY(QVariant StringFields READ getStringFields)

public:
    Entry();
    Entry(QString name, QString login, QString password, QString uuid);
    Entry(const Entry & other);
    Entry &operator =(const Entry &other);

    QString login() const;
    QString password() const;
    QString uuid() const;
    QString name() const;
    QList<StringField> stringFields() const;
    void addStringField(const QString& key, const QString& value);

private:
    QVariant getStringFields() const;

    QString m_login;
    QString m_password;
    QString m_uuid;
    QString m_name;
    QList<StringField> m_stringFields;
};

class Response
{
public:
    Response(const Request &request, QString hash);

    void setError(const QString &error = QString());
    void setSuccess();
    void setId(const QString &id);
    void setEntries(const QList<Entry> &entries);
    void setVerifier(QString key);
    void setCount(int count);

    QString toJson();

private:
    SymmetricCipher m_cipher;
    QJsonObject m_jsonObject;
};

}/*namespace KeepassHttpProtocol*/

#endif // RESPONSE_H
