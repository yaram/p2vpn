#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h> 
#include <iphlpapi.h>
#include <assert.h>
#include "juice/juice.h"
#include "wintun.h"
#define CBASE64_IMPLEMENTATION
#include "cbase64.h"
#include "qapplication.h"
#include "qclipboard.h"
#include "qmainwindow.h"
#include "qboxlayout.h"
#include "qstackedwidget.h"
#include "qlabel.h"
#include "qlineedit.h"
#include "qpushbutton.h"
#include "qplugin.h"

static WINTUN_ENUM_ADAPTERS_FUNC WintunEnumAdapters;
static WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter;
static WINTUN_OPEN_ADAPTER_FUNC WintunOpenAdapter;
static WINTUN_GET_ADAPTER_NAME_FUNC WintunGetAdapterName;
static WINTUN_GET_ADAPTER_LUID_FUNC WintunGetAdapterLUID;
static WINTUN_START_SESSION_FUNC WintunStartSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC WintunSendPacket;
static WINTUN_END_SESSION_FUNC WintunEndSession;
static WINTUN_FREE_ADAPTER_FUNC WintunFreeAdapter;

static void base64_encode(const uint8_t *data, size_t data_length, char *buffer) {
    cbase64_encodestate encode_state;
    cbase64_init_encodestate(&encode_state);

    auto length_written = (size_t)cbase64_encode_block(
        data,
        (unsigned int)data_length,
        buffer,
        &encode_state
    );

    length_written += cbase64_encode_blockend(&(buffer[length_written]), &encode_state);

    buffer[length_written] = '\0';
}

static size_t base64_decode(const char *base64_string, uint8_t *buffer) {
    cbase64_decodestate decode_state;
    cbase64_init_decodestate(&decode_state);

    auto length_written = (size_t)cbase64_decode_block(
        base64_string,
        (unsigned int)strlen(base64_string),
        buffer,
        &decode_state
    );

    return length_written;
}

static size_t base64_decoded_length(const char *base64_string) {
    return (size_t)cbase64_calc_decoded_length(base64_string, (unsigned int)strlen(base64_string));
}

const static size_t max_description_length = JUICE_MAX_SDP_STRING_LEN - 1;
const static size_t max_description_encoded_length = max_description_length;
const static size_t max_description_encoded_base64_length = 4 * ((max_description_encoded_length - 1) / 3) + (((max_description_encoded_length - 1) % 3 != 0) ? 4 : 0);

static void encode_string(const char *source, size_t *source_index, uint8_t *destination, size_t *destination_index, char terminator) {
    auto start = *source_index;

    while(source[*source_index] != terminator) {
        *source_index += 1;
    }

    auto end = *source_index;
    *source_index += 1;

    auto length = (uint8_t)(end - start);

    destination[*destination_index] = length;
    *destination_index += 1;

    memcpy(&destination[*destination_index], &source[start], length);
    *destination_index += length;
}

static size_t encode_description(const char *description, uint8_t *buffer) {
    size_t index = 0;
    size_t buffer_index = 0;

    // Don't bother verifying format of descriptor for now, very unsafe, much jank

    index += strlen("a=ice-ufrag:");
    encode_string(description, &index, buffer, &buffer_index, '\n'); // Password

    index += strlen("a=ice-pwd:");
    encode_string(description, &index, buffer, &buffer_index, '\n'); // Username

    while(true) {
        index += strlen("a=");

        if(description[index] != 'c') {
            break;
        }

        index += strlen("candidate:");

        encode_string(description, &index, buffer, &buffer_index, ' ');

        {
            auto start = index;

            while(isdigit(description[index])) {
                index += 1;
            }

            index += 1;

            auto value =  (uint8_t)(strtoull(&description[start], nullptr, 10) - 1);

            buffer[buffer_index] = value;
            buffer_index += 1;
        }

        index += strlen("UDP ");

        {
            auto start = index;

            while(isdigit(description[index])) {
                index += 1;
            }

            index += 1;

            auto value =  (uint32_t)strtoull(&description[start], nullptr, 10);

            buffer[buffer_index] = (uint8_t)value;
            buffer[buffer_index + 1] = (uint8_t)(value >> 8);
            buffer[buffer_index + 2] = (uint8_t)(value >> 16);
            buffer[buffer_index + 3] = (uint8_t)(value >> 24);
            buffer_index += 4;
        }

        encode_string(description, &index, buffer, &buffer_index, ' ');

        {
            auto start = index;

            while(isdigit(description[index])) {
                index += 1;
            }

            index += 1;

            auto value =  (uint16_t)strtoull(&description[start], nullptr, 10);

            buffer[buffer_index] = (uint8_t)value;
            buffer[buffer_index + 1] = (uint8_t)(value >> 8);
            buffer_index += 2;
        }

        encode_string(description, &index, buffer, &buffer_index, '\n');
    }

    // description[index] == 'e' (end-of-candidates)

    return buffer_index;
}

static bool output_character(char *destination, size_t destination_size, size_t *index, char character) {
    if(*index == destination_size) {
        return false;
    }

    destination[*index] = character;
    *index += 1;

    return true;
}

static bool output_string(char *destination, size_t destination_size, size_t *index, const char *string) {
    auto length = strlen(string);

    if(destination_size - *index < length) {
        return false;
    }

    memcpy(&destination[*index], string, length);
    *index += length;

    return true;
}

static bool decode_string(
    uint8_t *source,
    size_t source_length,
    size_t *source_index,
    char *destination,
    size_t destination_length,
    size_t *destination_index
) {
    if(*source_index == source_length) {
        return false;
    }

    auto length = source[*source_index];
    *source_index += 1;

    if(source_length - *source_index < length) {
        return false;
    }

    if(destination_length - *destination_index < length) {
        return false;
    }

    memcpy(&destination[*destination_index], &source[*source_index], length);
    *destination_index += length;
    *source_index += length;

    return true;
}

#define check(expression) if(!expression) { return false; }

static bool decode_description(uint8_t *bytes, size_t bytes_length, char *buffer, size_t buffer_length) {
    size_t index = 0;
    size_t buffer_index = 0;

    check(output_string(buffer, buffer_length, &buffer_index, "a=ice-ufrag:"));
    check(decode_string(bytes, bytes_length, &index, buffer, buffer_length, &buffer_index));
    check(output_character(buffer, buffer_length, &buffer_index, '\n'));

    check(output_string(buffer, buffer_length, &buffer_index, "a=ice-pwd:"));
    check(decode_string(bytes, bytes_length, &index, buffer, buffer_length, &buffer_index));
    check(output_character(buffer, buffer_length, &buffer_index, '\n'));

    while(index != bytes_length) {
        check(output_string(buffer, buffer_length, &buffer_index, "a=candidate:"));

        check(decode_string(bytes, bytes_length, &index, buffer, buffer_length, &buffer_index));
        check(output_character(buffer, buffer_length, &buffer_index, ' '));

        {
            if(index == bytes_length) {
                return false;
            }

            auto value = (uint32_t)bytes[index] + 1;
            index += 1;

            char temp_buffer[32];
            auto length = (size_t)sprintf_s(temp_buffer, 32, "%u ", value);

            if(buffer_length - buffer_index < length) {
                return false;
            }

            memcpy(&buffer[buffer_index], temp_buffer, length);
            buffer_index += length;
        }

        check(output_string(buffer, buffer_length, &buffer_index, "UDP "));

        {
            if(bytes_length - index < 4) {
                return false;
            }

            auto value = (uint32_t)bytes[index] |
                (uint32_t)bytes[index + 1] << 8 |
                (uint32_t)bytes[index + 2] << 16 |
                (uint32_t)bytes[index + 3] << 24;
            index += 4;

            char temp_buffer[32];
            auto length = (size_t)sprintf_s(temp_buffer, 32, "%u ", value);

            if(buffer_length - buffer_index < length) {
                return false;
            }

            memcpy(&buffer[buffer_index], temp_buffer, length);
            buffer_index += length;
        }

        check(decode_string(bytes, bytes_length, &index, buffer, buffer_length, &buffer_index));
        check(output_character(buffer, buffer_length, &buffer_index, ' '));

        {
            if(bytes_length - index < 2) {
                return false;
            }

            auto value = (uint16_t)bytes[index] |
                (uint16_t)bytes[index + 1] << 8;
            index += 2;

            char temp_buffer[32];
            auto length = (size_t)sprintf_s(temp_buffer, 32, "%hu ", value);

            if(buffer_length - buffer_index < length) {
                return false;
            }

            memcpy(&buffer[buffer_index], temp_buffer, length);
            buffer_index += length;
        }

        check(decode_string(bytes, bytes_length, &index, buffer, buffer_length, &buffer_index));
        check(output_character(buffer, buffer_length, &buffer_index, '\n'));
    }

    check(output_string(buffer, buffer_length, &buffer_index, "a=end-of-candidates"));

    check(output_character(buffer, buffer_length, &buffer_index, '\0'));

    return true;
}

enum struct PacketType {
    IPAddress,
    Data
};

enum struct Page {
    Initial,
    Create,
    Connect,
    Connected
};

struct Context : QObject {
    WINTUN_SESSION_HANDLE wintun_session;

    juice_agent_t *juice_agent;

    uint32_t local_ip_address;
    uint32_t peer_ip_address;

    Page current_page;

    QClipboard *clipboard;

    QLabel *status_label;

    QStackedWidget *page_stack;

    QWidget *create_page_widget;
    QPushButton *create_page_local_connection_string_copy_button;
    QLineEdit *create_page_local_connection_string_edit;
    QLineEdit *create_page_remote_connection_string_edit;
    QPushButton *create_page_connect_button;

    QWidget *connect_page_widget;
    QPushButton *connect_page_local_connection_string_copy_button;
    QLineEdit *connect_page_local_connection_string_edit;
    QLineEdit *connect_page_remote_connection_string_edit;
    QPushButton *connect_page_generate_button;

    QWidget *connected_page_widget;
    QLineEdit *connected_page_peer_ip_address_edit;

    void on_create_page_button_pressed() {
        page_stack->setCurrentWidget(create_page_widget);

        juice_gather_candidates(juice_agent);

        current_page = Page::Create;
    }

    void on_connect_page_button_pressed() {
        page_stack->setCurrentWidget(connect_page_widget);

        current_page = Page::Connect;
    }

    void on_create_page_connect_button_pressed() {
        auto remote_description_encoded_base64 = create_page_remote_connection_string_edit->text().toUtf8();

        if(remote_description_encoded_base64.length() > max_description_encoded_base64_length) {
            status_label->setText("Remote connection string is invalid");
            status_label->setVisible(true);

            return;
        }

        remote_description_encoded_base64.append('\0');

        uint8_t remote_descriptor_encoded[max_description_encoded_length];
        auto remote_description_encoded_size = base64_decode(remote_description_encoded_base64.data(), remote_descriptor_encoded);

        char remote_descriptor[max_description_length + 1];
        if(!decode_description(remote_descriptor_encoded, remote_description_encoded_size, remote_descriptor, max_description_length + 1)) {
            status_label->setText("Remote connection string is invalid");
            status_label->setVisible(true);

            return;
        }

        if(juice_set_remote_description(juice_agent, remote_descriptor) != JUICE_ERR_SUCCESS) {
            status_label->setText("Remote connection string is invalid");
            status_label->setVisible(true);

            return;
        }

        page_stack->setCurrentWidget(connected_page_widget);

        current_page = Page::Connected;

        status_label->setText("Waiting for connection from peer...");
        status_label->setVisible(true);
    }

    void on_connect_page_generate_button_pressed() {
        auto remote_description_encoded_base64 = connect_page_remote_connection_string_edit->text().toUtf8();

        if(remote_description_encoded_base64.length() > max_description_encoded_base64_length) {
            status_label->setText("Remote connection string is invalid");
            status_label->setVisible(true);

            return;
        }

        remote_description_encoded_base64.append('\0');

        uint8_t remote_descriptor_encoded[max_description_encoded_length];
        auto remote_description_encoded_size = base64_decode(remote_description_encoded_base64.data(), remote_descriptor_encoded);

        char remote_descriptor[max_description_length + 1];
        if(!decode_description(remote_descriptor_encoded, remote_description_encoded_size, remote_descriptor, max_description_length + 1)) {
            status_label->setText("Remote connection string is invalid");
            status_label->setVisible(true);

            return;
        }

        if(juice_set_remote_description(juice_agent, remote_descriptor) != JUICE_ERR_SUCCESS) {
            status_label->setText("Remote connection string is invalid");
            status_label->setVisible(true);

            return;
        }

        connect_page_remote_connection_string_edit->setEnabled(false);
        connect_page_generate_button->setEnabled(false);

        juice_gather_candidates(juice_agent);

        status_label->setText("Waiting for connection from peer...");
        status_label->setVisible(true);
    }

    void on_local_connection_string_copy_button_pressed() {
        char local_description[max_description_length + 1];
        juice_get_local_description(juice_agent, local_description, max_description_length + 1);

        uint8_t local_description_encoded[max_description_encoded_length];
        auto local_description_encoded_length = encode_description(local_description, local_description_encoded);

        char local_description_encoded_base64[max_description_encoded_base64_length + 1];
        base64_encode(local_description_encoded, local_description_encoded_length, local_description_encoded_base64);

        clipboard->setText(QString(local_description_encoded_base64));
    }

    void on_gathering_done() {
        char local_description[max_description_length + 1];
        juice_get_local_description(juice_agent, local_description, max_description_length + 1);

        uint8_t local_description_encoded[max_description_encoded_length];
        auto local_description_encoded_length = encode_description(local_description, local_description_encoded);

        char local_description_encoded_base64[max_description_encoded_base64_length + 1];
        base64_encode(local_description_encoded, local_description_encoded_length, local_description_encoded_base64);

        switch(current_page) {
            case Page::Create: {
                create_page_local_connection_string_edit->setText(local_description_encoded_base64);
                create_page_local_connection_string_edit->setEnabled(true);
                create_page_remote_connection_string_edit->setEnabled(true);
                create_page_connect_button->setEnabled(true);
                create_page_local_connection_string_copy_button->setEnabled(true);
            } break;

            case Page::Connect: {
                connect_page_local_connection_string_edit->setText(local_description_encoded_base64);
                connect_page_local_connection_string_edit->setEnabled(true);
                connect_page_local_connection_string_copy_button->setEnabled(true);
            } break;
        }
    }

    void on_state_changed() {
        switch(juice_get_state(juice_agent)) {
            case JUICE_STATE_COMPLETED: {
                if(current_page == Page::Connect) {
                    page_stack->setCurrentWidget(connected_page_widget);

                    current_page = Page::Connected;
                }

                uint8_t ip_address_packet[5] {
                    (uint8_t)PacketType::IPAddress,
                    (uint8_t)(local_ip_address >> 24),
                    (uint8_t)(local_ip_address >> 16),
                    (uint8_t)(local_ip_address >> 8),
                    (uint8_t)local_ip_address
                };

                juice_send(juice_agent, (char*)ip_address_packet, 5);

                status_label->setText("Connected to peer!");
                status_label->setVisible(true);
            } break;

            case JUICE_STATE_FAILED: {
                if(current_page == Page::Connect) {
                    page_stack->setCurrentWidget(connected_page_widget);

                    current_page = Page::Connected;
                }

                status_label->setText("Disconnected from peer!");
                status_label->setVisible(true);
            } break;
        }
    }

    void on_peer_ip_address_received() {
        char ip_address_text[32];
        sprintf_s(
            ip_address_text,
            32,
            "%hhu.%hhu.%hhu.%hhu",
            (uint8_t)(peer_ip_address >> 24),
            (uint8_t)(peer_ip_address >> 16),
            (uint8_t)(peer_ip_address >> 8),
            (uint8_t)peer_ip_address
        );

        connected_page_peer_ip_address_edit->setText(ip_address_text);
        connected_page_peer_ip_address_edit->setEnabled(true);
    }
};

static void on_gathering_done(juice_agent_t *agent, void *user_ptr) {
    auto context = (Context*)user_ptr;

    QMetaObject::invokeMethod(context, &Context::on_gathering_done);
}

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
    auto context = (Context*)user_ptr;

    QMetaObject::invokeMethod(context, &Context::on_state_changed);
}

static void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
    auto context = (Context*)user_ptr;

    auto data_bytes = (const uint8_t*)data;

    switch((PacketType)data_bytes[0]) {
        case PacketType::IPAddress: {
            context->peer_ip_address =
                (uint32_t)data_bytes[1] << 24 |
                (uint32_t)data_bytes[2] << 16 |
                (uint32_t)data_bytes[3] << 8 |
                (uint32_t)data_bytes[4];

            QMetaObject::invokeMethod(context, &Context::on_peer_ip_address_received);
        } break;

        case PacketType::Data: {
            auto packet = WintunAllocateSendPacket(context->wintun_session, (DWORD)size);

            memcpy(packet, &data[1], size - 1);

            WintunSendPacket(context->wintun_session, packet);
        } break;
    }
}

struct EnumerationParameters {
    bool adapter_found;
    WCHAR adapter_name[MAX_ADAPTER_NAME];
};

static BOOL CALLBACK wintun_adapter_enumeration_callback(WINTUN_ADAPTER_HANDLE adapter, LPARAM parameter) {
    auto parameters = (EnumerationParameters*)parameter;

    parameters->adapter_found = true;

    WintunGetAdapterName(adapter, parameters->adapter_name);

    return FALSE;
}

static DWORD WINAPI packet_send_thread(LPVOID lpParameter) {
    auto context = (Context*)lpParameter;

    auto wintun_wait_handle = WintunGetReadWaitEvent(context->wintun_session);

    while(true) {
        DWORD packet_data_size;
        auto packet_data = WintunReceivePacket(context->wintun_session, &packet_data_size);

        if(packet_data != nullptr) {
            if(juice_get_state(context->juice_agent) == JUICE_STATE_COMPLETED) {
                auto packet_size = 1 + (size_t)packet_data_size;
                auto packet = (uint8_t*)malloc(packet_size);

                packet[0] = (uint8_t)PacketType::Data;

                memcpy(&packet[1], packet_data, packet_data_size);

                juice_send(context->juice_agent, (char*)packet, packet_size);
            }

            WintunReleaseReceivePacket(context->wintun_session, packet_data);
        } else {
            WaitForSingleObject(wintun_wait_handle, INFINITE);
        }
    }
}

#define IP_CONSTANT(a, b, c, d) ((uint32_t)d | (uint32_t)c << 8 | (uint32_t)b << 16 | (uint32_t)a << 24)

static bool entry() {
    auto wintun_library = LoadLibraryA("wintun.dll");

    WintunEnumAdapters = (WINTUN_ENUM_ADAPTERS_FUNC)GetProcAddress(wintun_library, "WintunEnumAdapters");
    WintunCreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC)GetProcAddress(wintun_library, "WintunCreateAdapter");
    WintunOpenAdapter = (WINTUN_OPEN_ADAPTER_FUNC)GetProcAddress(wintun_library, "WintunOpenAdapter");
    WintunGetAdapterName = (WINTUN_GET_ADAPTER_NAME_FUNC)GetProcAddress(wintun_library, "WintunGetAdapterName");
    WintunGetAdapterLUID = (WINTUN_GET_ADAPTER_LUID_FUNC)GetProcAddress(wintun_library, "WintunGetAdapterLUID");
    WintunStartSession = (WINTUN_START_SESSION_FUNC)GetProcAddress(wintun_library, "WintunStartSession");
    WintunGetReadWaitEvent = (WINTUN_GET_READ_WAIT_EVENT_FUNC)GetProcAddress(wintun_library, "WintunGetReadWaitEvent");
    WintunReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC)GetProcAddress(wintun_library, "WintunReceivePacket");
    WintunReleaseReceivePacket = (WINTUN_RELEASE_RECEIVE_PACKET_FUNC)GetProcAddress(wintun_library, "WintunReleaseReceivePacket");
    WintunAllocateSendPacket = (WINTUN_ALLOCATE_SEND_PACKET_FUNC)GetProcAddress(wintun_library, "WintunAllocateSendPacket");
    WintunSendPacket = (WINTUN_SEND_PACKET_FUNC)GetProcAddress(wintun_library, "WintunSendPacket");
    WintunEndSession = (WINTUN_END_SESSION_FUNC)GetProcAddress(wintun_library, "WintunEndSession");
    WintunFreeAdapter = (WINTUN_FREE_ADAPTER_FUNC)GetProcAddress(wintun_library, "WintunFreeAdapter");

    auto pool_name = L"P2PVPN";

    EnumerationParameters enum_parameters {};
    WintunEnumAdapters(pool_name, wintun_adapter_enumeration_callback, (LPARAM)&enum_parameters);

    WINTUN_ADAPTER_HANDLE wintun_adapter;
    if(enum_parameters.adapter_found) {
        wintun_adapter = WintunOpenAdapter(pool_name, enum_parameters.adapter_name);
    } else {
        // {CA88F39E-7B30-4AC1-8A08-EFF4220C133A}
        const GUID guid { 0xca88f39e, 0x7b30, 0x4ac1, { 0x8a, 0x8, 0xef, 0xf4, 0x22, 0xc, 0x13, 0x3a } };
        wintun_adapter = WintunCreateAdapter(pool_name, L"P2P VPN Adapter", &guid, nullptr);
    }

    auto wintun_session = WintunStartSession(wintun_adapter, 0x400000);

    Context context;
    context.wintun_session = wintun_session;

    const uint32_t ip_subnet_prefix = IP_CONSTANT(100, 64, 0, 0);
    const uint32_t ip_subnet_length = 10;
    const uint32_t ip_subnet_mask = ~0u << (32u - ip_subnet_length); // Crazy bit stuff to calculate subnet mask

    srand((unsigned int)time(nullptr));

    uint32_t ip_address;

    ip_address = (uint32_t)rand();

    ip_address &= ~ip_subnet_mask;

    ip_address |= ip_subnet_prefix;

    context.local_ip_address = ip_address;

    NET_LUID wintun_adapter_luid;
    WintunGetAdapterLUID(wintun_adapter, &wintun_adapter_luid);

    // Clear existing IPv4 addresses from adapter with windows craziness

    MIB_UNICASTIPADDRESS_TABLE *address_table;
    GetUnicastIpAddressTable(AF_INET, &address_table);

    for(size_t i = 0; i < address_table->NumEntries; i += 1) {
        if(memcmp(&address_table->Table[i].InterfaceLuid, &wintun_adapter_luid, sizeof(NET_LUID)) == 0) {
            DeleteUnicastIpAddressEntry(&address_table->Table[i]);
        }
    }

    FreeMibTable(address_table);

    // Assign new IPv4 address to adapter with windows craziness

    MIB_UNICASTIPADDRESS_ROW address_row;
    InitializeUnicastIpAddressEntry(&address_row);

    address_row.Address.Ipv4.sin_family = AF_INET;
    address_row.Address.Ipv4.sin_addr.S_un.S_un_b.s_b1 = (uint8_t)(ip_address >> 24);
    address_row.Address.Ipv4.sin_addr.S_un.S_un_b.s_b2 = (uint8_t)(ip_address >> 16);
    address_row.Address.Ipv4.sin_addr.S_un.S_un_b.s_b3 = (uint8_t)(ip_address >> 8);
    address_row.Address.Ipv4.sin_addr.S_un.S_un_b.s_b4 = (uint8_t)ip_address;

    address_row.InterfaceLuid = wintun_adapter_luid;

    address_row.OnLinkPrefixLength = ip_subnet_length;

    CreateUnicastIpAddressEntry(&address_row);

    juice_config_t juice_config {};
    juice_config.stun_server_host = "stun.stunprotocol.org";
    juice_config.stun_server_port = 3478;

    juice_config.user_ptr = (void*)&context;

    juice_config.cb_state_changed = on_state_changed;
    juice_config.cb_gathering_done = on_gathering_done;
    juice_config.cb_recv = on_recv;

    auto juice_agent = juice_create(&juice_config);
    context.juice_agent = juice_agent;

    CreateThread(nullptr, 0, packet_send_thread, (void*)&context, 0, nullptr);

    int dummy_argc = 0;
    QApplication application(dummy_argc, nullptr);
    application.setStyle("Fusion");

    context.clipboard = application.clipboard();

    QMainWindow window;
    window.setWindowTitle("P2P VPN");

    QWidget central_widget;
    QVBoxLayout central_layout(&central_widget);
    window.setCentralWidget(&central_widget);

    QStackedWidget page_stack;
    central_layout.addWidget(&page_stack);
    context.page_stack = &page_stack;

    // Will probably clean this up eventually...

    // Initial page

    QWidget initial_page_widget;
    QVBoxLayout initial_page_layout(&initial_page_widget);
    page_stack.addWidget(&initial_page_widget);

    QPushButton initial_page_create_page_button("Create");
    QObject::connect(&initial_page_create_page_button, &QPushButton::clicked, &context, &Context::on_create_page_button_pressed);
    initial_page_layout.addWidget(&initial_page_create_page_button);

    QPushButton initial_page_connect_page_button("Connect");
    QObject::connect(&initial_page_connect_page_button, &QPushButton::clicked, &context, &Context::on_connect_page_button_pressed);
    initial_page_layout.addWidget(&initial_page_connect_page_button);

    // Create page

    QWidget create_page_widget;
    QVBoxLayout create_page_layout(&create_page_widget);
    page_stack.addWidget(&create_page_widget);
    context.create_page_widget = &create_page_widget;

    QLabel create_page_local_connection_string_label("Your connection string (send this to your peer)");
    create_page_layout.addWidget(&create_page_local_connection_string_label);

    QWidget create_page_local_connection_string_widget;
    QHBoxLayout create_page_local_connection_string_layout(&create_page_local_connection_string_widget);
    create_page_local_connection_string_layout.setContentsMargins(0, 0, 0, 0);
    create_page_layout.addWidget(&create_page_local_connection_string_widget);

    QLineEdit create_page_local_connection_string_edit("Loading...");
    create_page_local_connection_string_layout.addWidget(&create_page_local_connection_string_edit);
    create_page_local_connection_string_edit.setReadOnly(true);
    create_page_local_connection_string_edit.setDisabled(true);
    context.create_page_local_connection_string_edit = &create_page_local_connection_string_edit;

    QPushButton create_page_local_connection_string_copy_button("Copy");
    QObject::connect(&create_page_local_connection_string_copy_button, &QPushButton::clicked, &context, &Context::on_local_connection_string_copy_button_pressed);
    create_page_local_connection_string_layout.addWidget(&create_page_local_connection_string_copy_button);
    create_page_local_connection_string_copy_button.setDisabled(true);
    context.create_page_local_connection_string_copy_button = &create_page_local_connection_string_copy_button;

    QLabel create_page_remote_connection_string_label("Their connection string (your peer will send this to you)");
    create_page_layout.addWidget(&create_page_remote_connection_string_label);

    QLineEdit create_page_remote_connection_string_edit;
    create_page_layout.addWidget(&create_page_remote_connection_string_edit);
    create_page_remote_connection_string_edit.setDisabled(true);
    context.create_page_remote_connection_string_edit = &create_page_remote_connection_string_edit;

    QPushButton create_page_connect_button("Connect to peer");
    create_page_layout.addWidget(&create_page_connect_button);
    QObject::connect(&create_page_connect_button, &QPushButton::clicked, &context, &Context::on_create_page_connect_button_pressed);
    context.create_page_connect_button = &create_page_connect_button;

    // Connect page

    QWidget connect_page_widget;
    QVBoxLayout connect_page_layout(&connect_page_widget);
    page_stack.addWidget(&connect_page_widget);
    context.connect_page_widget = &connect_page_widget;

    QLabel connect_page_remote_connection_string_label("Their connection string (your peer will send this to you)");
    connect_page_layout.addWidget(&connect_page_remote_connection_string_label);

    QLineEdit connect_page_remote_connection_string_edit;
    connect_page_layout.addWidget(&connect_page_remote_connection_string_edit);
    context.connect_page_remote_connection_string_edit = &connect_page_remote_connection_string_edit;

    QPushButton connect_page_generate_button("Generate connection string");
    connect_page_layout.addWidget(&connect_page_generate_button);
    QObject::connect(&connect_page_generate_button, &QPushButton::clicked, &context, &Context::on_connect_page_generate_button_pressed);
    context.connect_page_generate_button = &connect_page_generate_button;

    QLabel connect_page_local_connection_string_label("Your connection string (send this to your peer)");
    connect_page_layout.addWidget(&connect_page_local_connection_string_label);

    QWidget connect_page_local_connection_string_widget;
    QHBoxLayout connect_page_local_connection_string_layout(&connect_page_local_connection_string_widget);
    connect_page_local_connection_string_layout.setContentsMargins(0, 0, 0, 0);
    connect_page_layout.addWidget(&connect_page_local_connection_string_widget);

    QLineEdit connect_page_local_connection_string_edit;
    connect_page_local_connection_string_layout.addWidget(&connect_page_local_connection_string_edit);
    connect_page_local_connection_string_edit.setReadOnly(true);
    connect_page_local_connection_string_edit.setDisabled(true);
    context.connect_page_local_connection_string_edit = &connect_page_local_connection_string_edit;

    QPushButton connect_page_local_connection_string_copy_button("Copy");
    QObject::connect(&connect_page_local_connection_string_copy_button, &QPushButton::clicked, &context, &Context::on_local_connection_string_copy_button_pressed);
    connect_page_local_connection_string_layout.addWidget(&connect_page_local_connection_string_copy_button);
    connect_page_local_connection_string_copy_button.setDisabled(true);
    context.connect_page_local_connection_string_copy_button = &connect_page_local_connection_string_copy_button;

    // Connected page

    QWidget connected_page_widget;
    QVBoxLayout connected_page_layout(&connected_page_widget);
    page_stack.addWidget(&connected_page_widget);
    context.connected_page_widget = &connected_page_widget;

    QWidget connected_page_ip_address_widget;
    QHBoxLayout ip_address_layout(&connected_page_ip_address_widget);
    connected_page_layout.addWidget(&connected_page_ip_address_widget);

    QLabel connected_page_ip_address_label("Your IP address is:");
    ip_address_layout.addWidget(&connected_page_ip_address_label);

    char ip_address_text[32];
    sprintf_s(
        ip_address_text,
        32,
        "%hhu.%hhu.%hhu.%hhu",
        (uint8_t)(ip_address >> 24),
        (uint8_t)(ip_address >> 16),
        (uint8_t)(ip_address >> 8),
        (uint8_t)ip_address
    );

    QLineEdit connected_page_ip_address_edit(ip_address_text);
    ip_address_layout.addWidget(&connected_page_ip_address_edit);
    connected_page_ip_address_edit.setReadOnly(true);

    QLineEdit connected_page_peer_ip_address_edit;
    connected_page_layout.addWidget(&connected_page_peer_ip_address_edit);
    connected_page_peer_ip_address_edit.setReadOnly(true);
    connected_page_peer_ip_address_edit.setDisabled(true);

    QWidget connected_page_peer_ip_address_widget;
    QHBoxLayout peer_ip_address_layout(&connected_page_peer_ip_address_widget);
    connected_page_layout.addWidget(&connected_page_peer_ip_address_widget);

    QLabel connected_page_peer_ip_address_label("Your peer's IP address is:");
    peer_ip_address_layout.addWidget(&connected_page_peer_ip_address_label);

    QLineEdit peer_ip_address_edit;
    peer_ip_address_layout.addWidget(&connected_page_peer_ip_address_edit);
    peer_ip_address_edit.setReadOnly(true);
    peer_ip_address_edit.setDisabled(true);
    context.connected_page_peer_ip_address_edit = &connected_page_peer_ip_address_edit;

    QLabel status_label;
    status_label.setVisible(false);
    central_layout.addWidget(&status_label);
    context.status_label = &status_label;

    window.show();

    application.exec();

    return 0;
}

#ifdef WINDOWS_SUBSYSTEM
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR pCmdLine, int nCmdShow) {
    if(entry()) {
        return 0;
    } else {
        return 1;
    }
}
#else
int main(int argc, char *argv[]) {
    if(entry()) {
        return 0;
    } else {
        return 1;
    }
}
#endif

Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin)