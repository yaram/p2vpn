qt_internal_add_plugin(QTlsBackendCertOnlyPlugin
    OUTPUT_NAME certonlybackend
    CLASS_NAME QTlsBackendCertOnly
    PLUGIN_TYPE tls
    DEFAULT_IF NOT QT_FEATURE_securetransport AND NOT (QT_FEATURE_openssl OR QT_FEATURE_openssl_linked) AND NOT QT_FEATURE_schannel
    SOURCES
        ../shared/qx509_base_p.h
        ../shared/qx509_base.cpp
        ../shared/qx509_generic_p.h
        ../shared/qx509_generic.cpp
        ../shared/qasn1element_p.h
        ../shared/qasn1element.cpp
        qtlsbackend_cert.cpp
        qtlsbackend_cert_p.h
    LIBRARIES
        Qt::NetworkPrivate
)
