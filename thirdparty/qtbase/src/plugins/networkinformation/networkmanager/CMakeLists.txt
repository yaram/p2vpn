qt_internal_add_plugin(QNetworkManagerNetworkInformationPlugin
    OUTPUT_NAME networkmanager
    CLASS_NAME QNetworkManagerNetworkInformationBackendFactory
    PLUGIN_TYPE networkinformation
    DEFAULT_IF LINUX
    SOURCES
        qnetworkmanagernetworkinformationbackend.cpp
        qnetworkmanagerservice.h
        qnetworkmanagerservice.cpp
    LIBRARIES
        Qt::DBus
        Qt::NetworkPrivate
)
