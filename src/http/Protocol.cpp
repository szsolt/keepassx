/**
 ***************************************************************************
 * @file Response.cpp
 *
 * @brief
 *
 * Copyright (C) 2013
 *
 * @author	Francois Ferrand
 * @date	4/2013
 ***************************************************************************
 */

#include "Protocol.h"

#include <QtCore/QMetaProperty>
#include <QtCore/QStringList>
#include <QtCore/QVariant>
#include <QtCore/QDebug>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonArray>

#include "crypto/Random.h"
#include "crypto/SymmetricCipher.h"

namespace KeepassHttpProtocol
{
static const char * const STR_GET_LOGINS = "get-logins";
static const char * const STR_GET_LOGINS_COUNT = "get-logins-count";
static const char * const STR_GET_ALL_LOGINS = "get-all-logins";
static const char * const STR_SET_LOGIN = "set-login";
static const char * const STR_ASSOCIATE = "associate";
static const char * const STR_TEST_ASSOCIATE = "test-associate";
static const char * const STR_GENERATE_PASSWORD = "generate-password";
static const char * const STR_VERSION = "1.8.0.0";

}/*namespace KeepassHttpProtocol*/

using namespace KeepassHttpProtocol;

static QHash<QString, RequestType> createStringHash()
{
    QHash<QString, RequestType> hash;
    hash.insert(STR_GET_LOGINS,       GET_LOGINS);
    hash.insert(STR_GET_LOGINS_COUNT, GET_LOGINS_COUNT);
    hash.insert(STR_GET_ALL_LOGINS,   GET_ALL_LOGINS);
    hash.insert(STR_SET_LOGIN,        SET_LOGIN);
    hash.insert(STR_ASSOCIATE,        ASSOCIATE);
    hash.insert(STR_TEST_ASSOCIATE,   TEST_ASSOCIATE);
    hash.insert(STR_GENERATE_PASSWORD,GENERATE_PASSWORD);
    return hash;
}

static RequestType parseRequest(const QString &str)
{
    static const QHash<QString, RequestType> REQUEST_STRINGS = createStringHash();
    return REQUEST_STRINGS.value(str, INVALID);
}

static QByteArray decode64(QString s)
{
    return QByteArray::fromBase64(s.toLatin1());
}

static QString encode64(QByteArray b)
{
    return QString::fromLatin1(b.toBase64());
}

static QByteArray decrypt2(const QByteArray & data, SymmetricCipher & cipher)
{
    //Ensure we get full blocks only
    if (data.length() <= 0 || data.length() % cipher.blockSize())
        return QByteArray();

    //Decrypt
    cipher.reset();
    QByteArray buffer = cipher.process(data);

    //Remove PKCS#7 padding
    buffer.chop(buffer.at(buffer.length()-1));
    return buffer;
}

static QString decrypt(const QString &data, SymmetricCipher &cipher)
{
    return QString::fromUtf8(decrypt2(decode64(data), cipher));
}

static QByteArray encrypt2(const QByteArray & data, SymmetricCipher & cipher)
{
    //Add PKCS#7 padding
    const int blockSize = cipher.blockSize();
    const int paddingSize = blockSize - data.size() % blockSize;

    //Encrypt
    QByteArray buffer = data + QByteArray(paddingSize, paddingSize);
    cipher.reset();
    cipher.processInPlace(buffer);
    return buffer;
}

static QString encrypt(const QString & data, SymmetricCipher & cipher)
{
    return encode64(encrypt2(data.toUtf8(), cipher));
}


////////////////////////////////////////////////////////////////////////////////////////////////////
/// Request
////////////////////////////////////////////////////////////////////////////////////////////////////

Request::Request(): m_requestType(INVALID)
{
}

QString Request::get(const QString& key) const
{
    QJsonValue v = m_jsonObject[key];
    return v.isUndefined() ? QString() : v.toString();
    QJsonObject::const_iterator it = m_jsonObject.find(key);
    return it == m_jsonObject.constEnd() ? QString() : (*it).toString();
}

QString Request::requestTypeStr() const
{
    return get("RequestType");
}

QString Request::nonce() const
{
    return get("Nonce");
}

QString Request::verifier() const
{
    return get("Verifier");
}

QString Request::id() const
{
    return get("Id");
}

QString Request::key() const
{
    return get("Key");
}

QString Request::submitUrl() const
{
    Q_ASSERT(m_cipher.isValid());
    return decrypt(get("SubmitUrl"), m_cipher);
}

QString Request::url() const
{
    Q_ASSERT(m_cipher.isValid());
    return decrypt(get("Url"), m_cipher);
}

QString Request::realm() const
{
    Q_ASSERT(m_cipher.isValid());
    return decrypt(get("Realm"), m_cipher);
}

QString Request::login() const
{
    Q_ASSERT(m_cipher.isValid());
    return decrypt(get("Login"), m_cipher);
}

QString Request::uuid() const
{
    Q_ASSERT(m_cipher.isValid());
    return decrypt(get("Uuid"), m_cipher);
}

QString Request::password() const
{
    Q_ASSERT(m_cipher.isValid());
    return decrypt(get("Password"), m_cipher);
}

bool Request::sortSelection() const
{
    return m_jsonObject["SortSelection"].toBool();
}

KeepassHttpProtocol::RequestType Request::requestType() const
{
    return m_requestType;
}

bool Request::CheckVerifier(const QString &key) const
{
    Q_ASSERT(!m_cipher.isValid());
    QString _nonce = nonce();
    m_cipher.init(SymmetricCipher::Aes256, SymmetricCipher::Cbc, SymmetricCipher::Decrypt,
                  decode64(key), decode64(_nonce));
    return decrypt(verifier(), m_cipher) == _nonce;
}

bool Request::fromJson(QString text)
{
    QJsonDocument d = QJsonDocument::fromJson(text.toUtf8());
    m_jsonObject = d.object();
    if (d.isNull())
        return false;

    m_requestType = parseRequest(requestTypeStr());

    return m_requestType != INVALID;
}


////////////////////////////////////////////////////////////////////////////////////////////////////
/// Response
////////////////////////////////////////////////////////////////////////////////////////////////////

Response::Response(const Request &request, QString hash)
{
    m_jsonObject["Version"] = QString(STR_VERSION);
    m_jsonObject["Hash"] = hash;
    m_jsonObject["RequestType"] = request.requestTypeStr();
    m_jsonObject["Success"] = false;
}

void Response::setVerifier(QString key)
{
    Q_ASSERT(!m_cipher.isValid());
    m_cipher.init(SymmetricCipher::Aes256, SymmetricCipher::Cbc, SymmetricCipher::Encrypt, decode64(key));

    //Generate new IV
    const QByteArray iv = Random::randomArray(m_cipher.blockSize());
    m_cipher.setIv(iv);
    QString _nonce(encode64(iv));
    m_jsonObject["Nonce"] = _nonce;
    m_jsonObject["Verifier"] = encrypt(_nonce, m_cipher);
}

QString Response::toJson()
{
    QJsonDocument json(m_jsonObject);
    return json.toJson();
}

void Response::setEntries(const QList<Entry> &entries)
{
    Q_ASSERT(m_cipher.isValid());

    QJsonArray encEntries;
    Q_FOREACH (const Entry &entry, entries) {
        QJsonObject encryptedEntry;
        encryptedEntry["Name"] = encrypt(entry.name(), m_cipher);
        encryptedEntry["Login"] = encrypt(entry.login(), m_cipher);
        encryptedEntry["Password"] = entry.password().isNull() ? QString() : encrypt(entry.password(), m_cipher);
        encryptedEntry["Uuid"] = encrypt(entry.uuid(), m_cipher);
        Q_FOREACH (const StringField & field, entry.stringFields())
            encryptedEntry[encrypt(field.key(), m_cipher)] = encrypt(field.value(), m_cipher);
        encEntries.append(encryptedEntry);
    }
    setCount(encEntries.count());
    m_jsonObject["Entries"] = encEntries;
}

void Response::setId(const QString &id)
{
    m_jsonObject["Id"] = id;
}

void Response::setSuccess()
{
    m_jsonObject["Success"] = true;
}

void Response::setError(const QString &error)
{
    m_jsonObject["Success"] = false;
    m_jsonObject["Error"] = error;
}

void Response::setCount(int count)
{
    m_jsonObject["Count"] = count;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// Entry
////////////////////////////////////////////////////////////////////////////////////////////////////

//TODO: Replace Entry with QJsonObject ?

Entry::Entry()
{}

Entry::Entry(QString name, QString login, QString password, QString uuid):
    m_login(login),
    m_password(password),
    m_uuid(uuid),
    m_name(name)
{}

Entry::Entry(const Entry & other):
    QObject(),
    m_login(other.m_login),
    m_password(other.m_password),
    m_uuid(other.m_uuid),
    m_name(other.m_name),
    m_stringFields(other.m_stringFields)
{}

Entry & Entry::operator=(const Entry & other)
{
    m_login = other.m_login;
    m_password = other.m_password;
    m_uuid = other.m_uuid;
    m_name = other.m_name;
    m_stringFields = other.m_stringFields;
    return *this;
}

QString Entry::login() const
{
    return m_login;
}

QString Entry::name() const
{
    return m_name;
}

QString Entry::uuid() const
{
    return m_uuid;
}

QString Entry::password() const
{
    return m_password;
}

QList<StringField> Entry::stringFields() const
{
    return m_stringFields;
}

void Entry::addStringField(const QString &key, const QString &value)
{
    m_stringFields.append(StringField(key, value));
}

QVariant Entry::getStringFields() const
{
    if (m_stringFields.isEmpty())
        return QVariant();

    QList<QVariant> res;
    res.reserve(m_stringFields.size());
    /*
    Q_FOREACH (const StringField &stringfield, m_stringFields)
        res.append(QJson::QObjectHelper::qobject2qvariant(&stringfield, QJson::QObjectHelper::Flag_None));
    */
    return res;
}


////////////////////////////////////////////////////////////////////////////////////////////////////
/// StringField
////////////////////////////////////////////////////////////////////////////////////////////////////

StringField::StringField()
{}

StringField::StringField(const QString &key, const QString &value):
    m_key(key), m_value(value)
{}

StringField::StringField(const StringField &other):
    QObject(NULL), m_key(other.m_key), m_value(other.m_value)
{}

StringField &StringField::operator =(const StringField &other)
{
    m_key = other.m_key;
    m_value = other.m_value;
    return *this;
}

QString StringField::key() const
{
    return m_key;
}

QString StringField::value() const
{
    return m_value;
}
