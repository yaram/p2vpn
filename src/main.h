#include "juice/juice.h"
#include "wintun.h"
#include "qclipboard.h"
#include "qmainwindow.h"
#include "qstackedwidget.h"
#include "qboxlayout.h"
#include "qlabel.h"
#include "qlineedit.h"
#include "qpushbutton.h"

struct InitialPage : QWidget {
    Q_OBJECT

    public:

    InitialPage();

    signals:

    void open_create_page();
    void open_connect_page();
};

struct CreatePage : QWidget {
    Q_OBJECT

    public:

    QLineEdit *local_connection_string_edit;
    QPushButton *local_connection_string_copy_button;

    QLineEdit *remote_connection_string_edit;

    QPushButton *connect_button;

    QClipboard *clipboard;

    CreatePage(QClipboard *clipboard);

    signals:

    void connect_requested(QString remote_connection_string);

    public slots:

    void local_connection_string_acquired(QString local_connection_string);
    void local_connection_string_copy_button_clicked();
    void connect_button_clicked();
    void remote_connection_string_rejected();
};

struct ConnectPage : QWidget {
    Q_OBJECT

    public:

    QLineEdit *remote_connection_string_edit;

    QPushButton *generate_button;

    QLineEdit *local_connection_string_edit;
    QPushButton *local_connection_string_copy_button;

    QClipboard *clipboard;

    ConnectPage(QClipboard *clipboard);

    signals:

    void generate_requested(QString remote_connection_string);

    public slots:

    void generate_button_clicked();
    void remote_connection_string_rejected();
    void local_connection_string_acquired(QString local_connection_string);
    void local_connection_string_copy_button_clicked();
};

struct ConnectedPage : QWidget {
    Q_OBJECT

    public:

    QLineEdit *peer_ip_address_edit;

    ConnectedPage(QString ip_address_text);

    public slots:

    void peer_ip_address_received(QString peer_ip_address_text);
};

struct Window : QMainWindow {
    Q_OBJECT

    public:

    QStackedWidget *page_stack;

    InitialPage *initial_page;
    CreatePage *create_page;
    ConnectPage *connect_page;
    ConnectedPage *connected_page;

    QLabel *status_label;

    Window(QClipboard *clipboard, QString ip_address_text);

    signals:

    void connect_requested(QString remote_connection_string);
    void generate_requested(QString remote_connection_string);
    void acquire_local_connection_string();

    public slots:

    void open_create_page();
    void open_connect_page();
    void remote_connection_string_rejected();
    void local_connection_string_acquired(QString local_connection_string);
    void connection_made();
    void peer_ip_address_received(QString peer_ip_address_text);
    void status_message(QString message);
};

enum struct State {
    Initial,
    GatheringCandidates,
    AwaitingRemoteDescriptor,
    Connecting,
    Connected,
    Error
};

struct Context : QObject {
    Q_OBJECT

    public:

    WINTUN_SESSION_HANDLE wintun_session;

    juice_agent_t *juice_agent;

    uint32_t local_ip_address;
    uint32_t peer_ip_address;

    bool has_received_hello_packet;

    signals:

    void local_connection_string_acquired(QString local_connection_string);
    void remote_connection_string_rejected();
    void connection_made();
    void peer_ip_address_received(QString peer_ip_address_text);
    void status_message(QString message);

    public slots:

    void acquire_local_connection_string();
    void candidates_gathered();
    void connect_requested(QString remote_connection_string);
    void generate_requested(QString remote_connection_string);
    void juice_state_changed();
    void on_hello_packet_received();
};