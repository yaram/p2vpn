#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <winsock2.h>
#include <ws2ipdef.h> 
#include <iphlpapi.h>
#include <assert.h>
#include "juice/juice.h"
#include "wintun.h"
#define CBASE64_IMPLEMENTATION
#include "cbase64.h"
#include "tweetnacl.h"
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

extern "C" void randombytes(uint8_t *buffer, uint64_t buffer_size) {
    BCryptGenRandom(nullptr, buffer, buffer_size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

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

const size_t hello_packet_size = 5 + crypto_sign_PUBLICKEYBYTES + crypto_box_PUBLICKEYBYTES;

const size_t data_packet_header_size = 1;

enum struct PacketType {
    Hello,
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

    bool has_received_hello_packet;

    uint8_t local_signing_public_key[crypto_sign_PUBLICKEYBYTES];
    uint8_t signing_private_key[crypto_sign_SECRETKEYBYTES];

    uint8_t peer_signing_public_key[crypto_sign_PUBLICKEYBYTES];

    uint8_t local_box_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t box_private_key[crypto_box_SECRETKEYBYTES];

    uint8_t peer_box_public_key[crypto_box_PUBLICKEYBYTES];

    uint8_t box_shared_key[crypto_box_BEFORENMBYTES];

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

                uint8_t packet[hello_packet_size];

                packet[0] = (uint8_t)PacketType::Hello;

                packet[1] = (uint8_t)(local_ip_address >> 24);
                packet[2] = (uint8_t)(local_ip_address >> 16);
                packet[3] = (uint8_t)(local_ip_address >> 8);
                packet[4] = (uint8_t)local_ip_address;

                memcpy(&packet[5], local_signing_public_key, crypto_sign_PUBLICKEYBYTES);

                memcpy(&packet[5 + crypto_sign_PUBLICKEYBYTES], local_box_public_key, crypto_box_PUBLICKEYBYTES);

                juice_send(juice_agent, (char*)packet, hello_packet_size);

                if(!has_received_hello_packet) {
                    status_label->setText("Encrypting connection to peer...");
                    status_label->setVisible(true);
                }
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

    void on_hello_packet_received() {
        crypto_box_beforenm(box_shared_key, peer_box_public_key, box_private_key);

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

        status_label->setText("Connected to peer!");
        status_label->setVisible(true);

        connected_page_peer_ip_address_edit->setText(ip_address_text);
        connected_page_peer_ip_address_edit->setEnabled(true);

        has_received_hello_packet = true;
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
        case PacketType::Hello: {
            if(size != hello_packet_size) {
                return;
            }

            context->peer_ip_address =
                (uint32_t)data_bytes[1] << 24 |
                (uint32_t)data_bytes[2] << 16 |
                (uint32_t)data_bytes[3] << 8 |
                (uint32_t)data_bytes[4];

            memcpy(context->peer_signing_public_key, &data_bytes[5], crypto_sign_PUBLICKEYBYTES);

            memcpy(context->peer_box_public_key, &data_bytes[5 + crypto_sign_PUBLICKEYBYTES], crypto_box_PUBLICKEYBYTES);

            QMetaObject::invokeMethod(context, &Context::on_hello_packet_received);
        } break;

        case PacketType::Data: {
            if(!context->has_received_hello_packet) {
                return;
            }

            if(size <= data_packet_header_size) {
                return;
            }

            auto signed_data_size = size - data_packet_header_size;
            auto signed_data = &data_bytes[1];

            if(signed_data_size <= crypto_sign_BYTES) {
                return;
            }

            auto unsigned_data = (uint8_t*)malloc(signed_data_size);

            size_t unsigned_data_size;
            auto sign_open_result = crypto_sign_open(
                unsigned_data,
                &unsigned_data_size,
                signed_data,
                signed_data_size,
                context->peer_signing_public_key
            );

            if(sign_open_result != 0) {
                free(unsigned_data);

                return;
            }

            auto nonce = unsigned_data;

            auto encrypted_data_size = unsigned_data_size - crypto_box_NONCEBYTES;
            auto encrypted_data = &unsigned_data[crypto_box_NONCEBYTES];

            auto box_buffer_size = crypto_box_BOXZEROBYTES + encrypted_data_size;

            auto box_open_input = (uint8_t*)malloc(box_buffer_size);

            memset(box_open_input, 0, crypto_box_BOXZEROBYTES);
            memcpy(&box_open_input[crypto_box_BOXZEROBYTES], encrypted_data, encrypted_data_size);

            auto box_open_output = (uint8_t*)malloc(box_buffer_size);

            auto box_open_result = crypto_box_open_afternm(
                box_open_output,
                box_open_input,
                box_buffer_size,
                nonce,
                context->box_shared_key
            );

            free(unsigned_data);

            free(box_open_input);

            if(box_open_result != 0) {
                free(box_open_output);

                return;
            }

            auto unencrypted_data_size = box_buffer_size - crypto_box_ZEROBYTES;
            auto unencrypted_data = &box_open_output[crypto_box_ZEROBYTES];

            auto packet = WintunAllocateSendPacket(context->wintun_session, (DWORD)unencrypted_data_size);

            memcpy(packet, unencrypted_data, unencrypted_data_size);
            free(box_open_output);

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
        WaitForSingleObject(wintun_wait_handle, INFINITE);

        DWORD packet_data_size;
        auto packet_data = WintunReceivePacket(context->wintun_session, &packet_data_size);

        if(packet_data == nullptr) {
            continue;
        }

        if(juice_get_state(context->juice_agent) != JUICE_STATE_COMPLETED) {
            WintunReleaseReceivePacket(context->wintun_session, packet_data);

            continue;
        }

        if(!context->has_received_hello_packet) {
            WintunReleaseReceivePacket(context->wintun_session, packet_data);

            continue;
        }

        auto box_buffer_size = crypto_box_ZEROBYTES + (size_t)packet_data_size;

        auto box_input = (uint8_t*)malloc(box_buffer_size);

        memset(box_input, 0, crypto_box_ZEROBYTES);
        memcpy(&box_input[crypto_box_ZEROBYTES], packet_data, (size_t)packet_data_size);

        WintunReleaseReceivePacket(context->wintun_session, packet_data);

        uint8_t nonce[crypto_box_NONCEBYTES];
        randombytes(nonce, crypto_box_NONCEBYTES);

        auto box_output = (uint8_t*)malloc(box_buffer_size);

        auto result = crypto_box_afternm(
            box_output,
            box_input,
            box_buffer_size,
            nonce,
            context->box_shared_key
        );

        free(box_input);

        if(result != 0) {
            free(box_output);

            continue;
        }

        auto encrypted_data_size = box_buffer_size - crypto_box_BOXZEROBYTES;
        auto encrypted_data = &box_output[crypto_box_BOXZEROBYTES];

        auto unsigned_data_size = crypto_box_NONCEBYTES + encrypted_data_size;
        auto unsigned_data = (uint8_t*)malloc(unsigned_data_size);

        memcpy(unsigned_data, nonce, crypto_box_NONCEBYTES);

        memcpy(&unsigned_data[crypto_box_NONCEBYTES], encrypted_data, encrypted_data_size);

        free(box_output);

        auto signed_data = (uint8_t*)malloc(crypto_sign_BYTES + unsigned_data_size);

        size_t signed_data_size;
        crypto_sign(signed_data, &signed_data_size, unsigned_data, unsigned_data_size, context->signing_private_key);

        free(unsigned_data);

        auto packet_size = data_packet_header_size + signed_data_size;
        auto packet = (uint8_t*)malloc(packet_size);

        packet[0] = (uint8_t)PacketType::Data;

        memcpy(
            &packet[1],
            signed_data,
            signed_data_size
        );
        free(signed_data);

        juice_send(context->juice_agent, (char*)packet, packet_size);

        free(packet);
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

    auto pool_name = L"P2VPN";

    EnumerationParameters enum_parameters {};
    WintunEnumAdapters(pool_name, wintun_adapter_enumeration_callback, (LPARAM)&enum_parameters);

    WINTUN_ADAPTER_HANDLE wintun_adapter;
    if(enum_parameters.adapter_found) {
        wintun_adapter = WintunOpenAdapter(pool_name, enum_parameters.adapter_name);
    } else {
        // {CA88F39E-7B30-4AC1-8A08-EFF4220C133A}
        const GUID guid { 0xca88f39e, 0x7b30, 0x4ac1, { 0x8a, 0x8, 0xef, 0xf4, 0x22, 0xc, 0x13, 0x3a } };
        wintun_adapter = WintunCreateAdapter(pool_name, L"P2VPN Virtual Adapter", &guid, nullptr);
    }

    auto wintun_session = WintunStartSession(wintun_adapter, 0x400000);

    Context context {};
    context.wintun_session = wintun_session;

    crypto_sign_keypair(context.local_signing_public_key, context.signing_private_key);

    crypto_box_keypair(context.local_box_public_key, context.box_private_key);

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

    auto thread_handle = CreateThread(nullptr, 0, packet_send_thread, (void*)&context, 0, nullptr);

    int dummy_argc = 0;
    QApplication application(dummy_argc, nullptr);
    application.setStyle("Fusion");

    context.clipboard = application.clipboard();

    QMainWindow window;
    window.setWindowTitle("P2VPN");

    auto central_widget = new QWidget;
    QVBoxLayout central_layout(central_widget);
    window.setCentralWidget(central_widget);

    auto page_stack = new QStackedWidget;
    central_layout.addWidget(page_stack);
    context.page_stack = page_stack;

    // Will probably clean this up eventually...

    // Initial page

    auto initial_page_widget = new QWidget;
    QVBoxLayout initial_page_layout(initial_page_widget);
    page_stack->addWidget(initial_page_widget);

    auto initial_page_create_page_button = new QPushButton("Create");
    QObject::connect(initial_page_create_page_button, &QPushButton::clicked, &context, &Context::on_create_page_button_pressed);
    initial_page_layout.addWidget(initial_page_create_page_button);

    auto initial_page_connect_page_button = new QPushButton("Connect");
    QObject::connect(initial_page_connect_page_button, &QPushButton::clicked, &context, &Context::on_connect_page_button_pressed);
    initial_page_layout.addWidget(initial_page_connect_page_button);

    // Create page

    auto create_page_widget = new QWidget;
    QVBoxLayout create_page_layout(create_page_widget);
    page_stack->addWidget(create_page_widget);
    context.create_page_widget = create_page_widget;

    auto create_page_local_connection_string_label = new QLabel("Your connection string (send this to your peer)");
    create_page_layout.addWidget(create_page_local_connection_string_label);

    auto create_page_local_connection_string_widget = new QWidget;
    QHBoxLayout create_page_local_connection_string_layout(create_page_local_connection_string_widget);
    create_page_local_connection_string_layout.setContentsMargins(0, 0, 0, 0);
    create_page_layout.addWidget(create_page_local_connection_string_widget);

    auto create_page_local_connection_string_edit = new QLineEdit("Loading...");
    create_page_local_connection_string_layout.addWidget(create_page_local_connection_string_edit);
    create_page_local_connection_string_edit->setReadOnly(true);
    create_page_local_connection_string_edit->setDisabled(true);
    context.create_page_local_connection_string_edit = create_page_local_connection_string_edit;

    auto create_page_local_connection_string_copy_button = new QPushButton("Copy");
    QObject::connect(create_page_local_connection_string_copy_button, &QPushButton::clicked, &context, &Context::on_local_connection_string_copy_button_pressed);
    create_page_local_connection_string_layout.addWidget(create_page_local_connection_string_copy_button);
    create_page_local_connection_string_copy_button->setDisabled(true);
    context.create_page_local_connection_string_copy_button = create_page_local_connection_string_copy_button;

    auto create_page_remote_connection_string_label = new QLabel("Their connection string (your peer will send this to you)");
    create_page_layout.addWidget(create_page_remote_connection_string_label);

    auto create_page_remote_connection_string_edit = new QLineEdit;
    create_page_layout.addWidget(create_page_remote_connection_string_edit);
    create_page_remote_connection_string_edit->setDisabled(true);
    context.create_page_remote_connection_string_edit = create_page_remote_connection_string_edit;

    auto create_page_connect_button = new QPushButton("Connect to peer");
    create_page_layout.addWidget(create_page_connect_button);
    QObject::connect(create_page_connect_button, &QPushButton::clicked, &context, &Context::on_create_page_connect_button_pressed);
    context.create_page_connect_button = create_page_connect_button;

    // Connect page

    auto connect_page_widget = new QWidget;
    QVBoxLayout connect_page_layout(connect_page_widget);
    page_stack->addWidget(connect_page_widget);
    context.connect_page_widget = connect_page_widget;

    auto connect_page_remote_connection_string_label = new QLabel("Their connection string (your peer will send this to you)");
    connect_page_layout.addWidget(connect_page_remote_connection_string_label);

    auto connect_page_remote_connection_string_edit = new QLineEdit;
    connect_page_layout.addWidget(connect_page_remote_connection_string_edit);
    context.connect_page_remote_connection_string_edit = connect_page_remote_connection_string_edit;

    auto connect_page_generate_button = new QPushButton("Generate connection string");
    connect_page_layout.addWidget(connect_page_generate_button);
    QObject::connect(connect_page_generate_button, &QPushButton::clicked, &context, &Context::on_connect_page_generate_button_pressed);
    context.connect_page_generate_button = connect_page_generate_button;

    auto connect_page_local_connection_string_label = new QLabel("Your connection string (send this to your peer)");
    connect_page_layout.addWidget(connect_page_local_connection_string_label);

    auto connect_page_local_connection_string_widget = new QWidget;
    QHBoxLayout connect_page_local_connection_string_layout(connect_page_local_connection_string_widget);
    connect_page_local_connection_string_layout.setContentsMargins(0, 0, 0, 0);
    connect_page_layout.addWidget(connect_page_local_connection_string_widget);

    auto connect_page_local_connection_string_edit = new QLineEdit;
    connect_page_local_connection_string_layout.addWidget(connect_page_local_connection_string_edit);
    connect_page_local_connection_string_edit->setReadOnly(true);
    connect_page_local_connection_string_edit->setDisabled(true);
    context.connect_page_local_connection_string_edit = connect_page_local_connection_string_edit;

    auto connect_page_local_connection_string_copy_button = new QPushButton("Copy");
    QObject::connect(connect_page_local_connection_string_copy_button, &QPushButton::clicked, &context, &Context::on_local_connection_string_copy_button_pressed);
    connect_page_local_connection_string_layout.addWidget(connect_page_local_connection_string_copy_button);
    connect_page_local_connection_string_copy_button->setDisabled(true);
    context.connect_page_local_connection_string_copy_button = connect_page_local_connection_string_copy_button;

    // Connected page

    auto connected_page_widget = new QWidget;
    QVBoxLayout connected_page_layout(connected_page_widget);
    page_stack->addWidget(connected_page_widget);
    context.connected_page_widget = connected_page_widget;

    auto connected_page_ip_address_widget = new QWidget;
    QHBoxLayout ip_address_layout(connected_page_ip_address_widget);
    connected_page_layout.addWidget(connected_page_ip_address_widget);

    auto connected_page_ip_address_label = new QLabel("Your IP address is:");
    ip_address_layout.addWidget(connected_page_ip_address_label);

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

    auto connected_page_ip_address_edit = new QLineEdit(ip_address_text);
    ip_address_layout.addWidget(connected_page_ip_address_edit);
    connected_page_ip_address_edit->setReadOnly(true);

    auto connected_page_peer_ip_address_edit = new QLineEdit;
    connected_page_layout.addWidget(connected_page_peer_ip_address_edit);
    connected_page_peer_ip_address_edit->setReadOnly(true);
    connected_page_peer_ip_address_edit->setDisabled(true);

    auto connected_page_peer_ip_address_widget = new QWidget;
    QHBoxLayout peer_ip_address_layout(connected_page_peer_ip_address_widget);
    connected_page_layout.addWidget(connected_page_peer_ip_address_widget);

    auto connected_page_peer_ip_address_label = new QLabel("Your peer's IP address is:");
    peer_ip_address_layout.addWidget(connected_page_peer_ip_address_label);

    auto peer_ip_address_edit = new QLineEdit;
    peer_ip_address_layout.addWidget(connected_page_peer_ip_address_edit);
    peer_ip_address_edit->setReadOnly(true);
    peer_ip_address_edit->setDisabled(true);
    context.connected_page_peer_ip_address_edit = connected_page_peer_ip_address_edit;

    auto status_label = new QLabel;
    status_label->setVisible(false);
    central_layout.addWidget(status_label);
    context.status_label = status_label;

    window.show();

    application.exec();

    TerminateThread(thread_handle, 0);

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