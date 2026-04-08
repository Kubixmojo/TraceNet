#include "ssl.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <ctime>
#include <cstring>
#include <sstream>
#include <iomanip>

// ── helpers ──────────────────────────────────────────────────────────────────

static std::string asn1_time_to_string(const ASN1_TIME* t) {
    if (!t) return "brak";
    struct tm tm_out = {};
    ASN1_TIME_to_tm(t, &tm_out);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tm_out);
    return buf;
}

static int asn1_time_days_left(const ASN1_TIME* t) {
    if (!t) return 0;
    int day = 0, sec = 0;
    ASN1_TIME_diff(&day, &sec, nullptr, t); // nullptr = teraz
    return day;
}

static std::string x509_name_field(X509_NAME* name, int nid) {
    if (!name) return "";
    int idx = X509_NAME_get_index_by_NID(name, nid, -1);
    if (idx < 0) return "";
    X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
    ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
    unsigned char* utf8 = nullptr;
    ASN1_STRING_to_UTF8(&utf8, data);
    std::string result = utf8 ? reinterpret_cast<char*>(utf8) : "";
    OPENSSL_free(utf8);
    return result;
}

// ── główna funkcja ────────────────────────────────────────────────────────────

SslResult ssl_check(const std::string& host, int port) {
    SslResult res;
    res.host = host;
    res.port = port;

    // init OpenSSL
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        res.error = "SSL_CTX_new failed";
        return res;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr); // nie weryfikuj CA — chcemy tylko cert
    SSL_CTX_set_default_verify_paths(ctx);

    // połącz przez BIO (wygodniejsze niż raw socket + SSL)
    std::string addr = host + ":" + std::to_string(port);
    BIO* bio = BIO_new_ssl_connect(ctx);
    if (!bio) {
        res.error = "BIO_new_ssl_connect failed";
        SSL_CTX_free(ctx);
        return res;
    }

    BIO_set_conn_hostname(bio, addr.c_str());

    // SNI — serwer wie dla jakiej domeny robimy handshake
    SSL* ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    if (ssl) SSL_set_tlsext_host_name(ssl, host.c_str());

    // timeout przez BIO nie istnieje wprost — używamy non-blocking + select
    // dla prostoty: blokujące z domyślnym SO_TIMEOUT
    if (BIO_do_connect(bio) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        res.error = std::string("Połączenie nieudane: ") + buf;
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return res;
    }

    if (BIO_do_handshake(bio) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        res.error = std::string("TLS handshake nieudany: ") + buf;
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return res;
    }

    // pobierz certyfikat
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        res.error = "Serwer nie przesłał certyfikatu";
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return res;
    }

    // subject CN
    X509_NAME* subj = X509_get_subject_name(cert);
    std::string cn = x509_name_field(subj, NID_commonName);
    res.subject = cn.empty() ? "(brak CN)" : "CN=" + cn;

    // issuer — preferuj Organization, fallback na CN
    X509_NAME* iss = X509_get_issuer_name(cert);
    std::string iss_o  = x509_name_field(iss, NID_organizationName);
    std::string iss_cn = x509_name_field(iss, NID_commonName);
    res.issuer = iss_o.empty() ? iss_cn : iss_o;

    // daty
    res.valid_from = asn1_time_to_string(X509_get_notBefore(cert));
    res.valid_to   = asn1_time_to_string(X509_get_notAfter(cert));
    res.days_left  = asn1_time_days_left(X509_get_notAfter(cert));
    res.expired    = (res.days_left < 0);

    // SANs (Subject Alternative Names)
    GENERAL_NAMES* sans = reinterpret_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr)
    );
    if (sans) {
        int count = sk_GENERAL_NAME_num(sans);
        for (int i = 0; i < count; i++) {
            GENERAL_NAME* name = sk_GENERAL_NAME_value(sans, i);
            if (name->type == GEN_DNS) {
                unsigned char* utf8 = nullptr;
                ASN1_STRING_to_UTF8(&utf8, name->d.dNSName);
                if (utf8) {
                    res.sans.push_back({ reinterpret_cast<char*>(utf8) });
                    OPENSSL_free(utf8);
                }
            }
        }
        GENERAL_NAMES_free(sans);
    }

    X509_free(cert);
    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    res.success = true;
    return res;
}