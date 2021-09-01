#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h> 
#include <iphlpapi.h>
#include <assert.h>
#include "juice/juice.h"
#include "wintun.h"
#define CBASE64_IMPLEMENTATION
#include "cbase64.h"
#include "ui.h"

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

enum struct Page {
    Initial,
    Create,
    Connect,
    Connected
};

struct Context {
    WINTUN_SESSION_HANDLE wintun_session;

    juice_agent_t *juice_agent;

    Page current_page;

    uiLabel *status_label;

    uiBox *initial_page_box;

    uiBox *create_page_box;
    uiEntry *create_page_local_connection_string_entry;
    uiEntry *create_page_remote_connection_string_entry;
    uiButton *create_page_connect_button;

    uiBox *connect_page_box;
    uiEntry *connect_page_local_connection_string_entry;
    uiEntry *connect_page_remote_connection_string_entry;
    uiButton *connect_page_generate_button;
};

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
    auto context = (Context*)user_ptr;

    switch(state) {
        case JUICE_STATE_COMPLETED: {
            if(context->current_page == Page::Connect) {
                uiControlHide(uiControl(context->connect_page_box));

                context->current_page = Page::Connected;
            }

            uiLabelSetText(context->status_label, "Connected to peer!");
            uiControlShow(uiControl(context->status_label));
        } break;

        case JUICE_STATE_FAILED: {
            if(context->current_page == Page::Connect) {
                uiControlHide(uiControl(context->connect_page_box));

                context->current_page = Page::Connected;
            }

            uiLabelSetText(context->status_label, "Disconnected from peer!");
            uiControlShow(uiControl(context->status_label));
        } break;
    }
}

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

static void on_gathering_done(juice_agent_t *agent, void *user_ptr) {
    auto context = (Context*)user_ptr;

    char local_description[max_description_length + 1];
    juice_get_local_description(context->juice_agent, local_description, max_description_length + 1);

    uint8_t local_description_encoded[max_description_encoded_length];
    auto local_description_encoded_length = encode_description(local_description, local_description_encoded);

    char local_description_encoded_base64[max_description_encoded_base64_length + 1];
    base64_encode(local_description_encoded, local_description_encoded_length, local_description_encoded_base64);

    switch(context->current_page) {
        case Page::Create: {
            uiEntrySetText(context->create_page_local_connection_string_entry, local_description_encoded_base64);
            uiControlEnable(uiControl(context->create_page_local_connection_string_entry));
            uiControlEnable(uiControl(context->create_page_remote_connection_string_entry));
            uiControlEnable(uiControl(context->create_page_connect_button));
        } break;

        case Page::Connect: {
            uiEntrySetText(context->connect_page_local_connection_string_entry, local_description_encoded_base64);
            uiControlEnable(uiControl(context->connect_page_local_connection_string_entry));
        } break;
    }
}

static void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
    auto context = (Context*)user_ptr;

    auto packet = WintunAllocateSendPacket(context->wintun_session, (DWORD)size);

    memcpy(packet, data, size);

    WintunSendPacket(context->wintun_session, packet);
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
        DWORD packet_size;
        auto packet = WintunReceivePacket(context->wintun_session, &packet_size);

        if(packet != nullptr) {
            if(juice_get_state(context->juice_agent) == JUICE_STATE_COMPLETED) {
                juice_send(context->juice_agent, (const char*)packet, packet_size);
            }

            WintunReleaseReceivePacket(context->wintun_session, packet);
        } else {
            WaitForSingleObject(wintun_wait_handle, INFINITE);
        }
    }
}

int on_window_closing(uiWindow *window, void *data) {
    uiQuit();

    return true;
}

void on_create_page_connect_button_pressed(uiButton *button, void *data) {
    auto context = (Context*)data;

    auto remote_description_encoded_base64 = uiEntryText(context->create_page_remote_connection_string_entry);

    if(base64_decoded_length(remote_description_encoded_base64) > max_description_length) {
        uiLabelSetText(context->status_label, "Remote connection string too long");
        uiControlShow(uiControl(context->status_label));

        return;
    }

    uint8_t remote_descriptor_encoded[max_description_encoded_length];
    auto remote_description_encoded_size = base64_decode(remote_description_encoded_base64, remote_descriptor_encoded);

    char remote_descriptor[max_description_length + 1];
    if(!decode_description(remote_descriptor_encoded, remote_description_encoded_size, remote_descriptor, max_description_length + 1)) {
        uiLabelSetText(context->status_label, "Remote connection string is invalid");
        uiControlShow(uiControl(context->status_label));

        return;
    }

    if(juice_set_remote_description(context->juice_agent, remote_descriptor) != JUICE_ERR_SUCCESS) {
        uiLabelSetText(context->status_label, "Remote connection string is invalid");
        uiControlShow(uiControl(context->status_label));

        return;
    }

    uiControlHide(uiControl(context->create_page_box));

    context->current_page = Page::Connected;

    uiLabelSetText(context->status_label, "Waiting for connection from peer...");
    uiControlShow(uiControl(context->status_label));
}

void on_connect_page_generate_button_pressed(uiButton *button, void *data) {
    auto context = (Context*)data;

    auto remote_description_encoded_base64 = uiEntryText(context->connect_page_remote_connection_string_entry);

    if(base64_decoded_length(remote_description_encoded_base64) > max_description_length) {
        uiLabelSetText(context->status_label, "Remote connection string too long");
        uiControlShow(uiControl(context->status_label));

        return;
    }

    uint8_t remote_descriptor_encoded[max_description_encoded_length];
    auto remote_description_encoded_size = base64_decode(remote_description_encoded_base64, remote_descriptor_encoded);

    char remote_descriptor[max_description_length + 1];
    if(!decode_description(remote_descriptor_encoded, remote_description_encoded_size, remote_descriptor, max_description_length + 1)) {
        uiLabelSetText(context->status_label, "Remote connection string is invalid");
        uiControlShow(uiControl(context->status_label));

        return;
    }

    if(juice_set_remote_description(context->juice_agent, remote_descriptor) != JUICE_ERR_SUCCESS) {
        uiLabelSetText(context->status_label, "Remote connection string is invalid");
        uiControlShow(uiControl(context->status_label));

        return;
    }

    uiControlDisable(uiControl(context->connect_page_remote_connection_string_entry));
    uiControlDisable(uiControl(context->connect_page_generate_button));

    juice_set_remote_description(context->juice_agent, remote_descriptor);

    juice_gather_candidates(context->juice_agent);

    uiLabelSetText(context->status_label, "Waiting for connection from peer...");
    uiControlShow(uiControl(context->status_label));
}

void on_create_page_button_pressed(uiButton *button, void *data) {
    auto context = (Context*)data;

    uiControlHide(uiControl(context->initial_page_box));
    uiControlShow(uiControl(context->create_page_box));

    juice_gather_candidates(context->juice_agent);

    context->current_page = Page::Create;
}

void on_connect_page_button_pressed(uiButton *button, void *data) {
    auto context = (Context*)data;

    uiControlHide(uiControl(context->initial_page_box));
    uiControlShow(uiControl(context->connect_page_box));

    context->current_page = Page::Connect;
}

#define IP_CONSTANT(a, b, c, d) ((uint32_t)d | (uint32_t)c << 8 | (uint32_t)b << 16 | (uint32_t)a << 24)

bool entry() {
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

    const uint32_t ip_subnet_prefix = IP_CONSTANT(100, 64, 0, 0);
    const uint32_t ip_subnet_length = 10;
    const uint32_t ip_subnet_mask = ~0u << (32u - ip_subnet_length); // Crazy bit stuff to calculate subnet mask

    srand((unsigned int)time(nullptr));

    uint32_t ip_address;

    ip_address = (uint32_t)rand();

    ip_address &= ~ip_subnet_mask;

    ip_address |= ip_subnet_prefix;

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

    Context context;
    context.wintun_session = wintun_session;

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

    uiInitOptions ui_init_options {};
    uiInit(&ui_init_options);

    auto window = uiNewWindow("P2P VPN", 200, 300, false);
    uiWindowSetMargined(window, true);
    uiWindowOnClosing(window, on_window_closing, nullptr);

    auto main_box = uiNewVerticalBox();
    uiWindowSetChild(window, uiControl(main_box));
    uiBoxSetPadded(main_box, true);

    { // Local IP address
        auto box = uiNewHorizontalBox();
        uiBoxAppend(main_box, uiControl(box), false);
        uiBoxSetPadded(box, true);

        auto label = uiNewLabel("Your IP address is:");
        uiBoxAppend(box, uiControl(label), false);

        auto entry = uiNewEntry();
        uiBoxAppend(box, uiControl(entry), true);
        uiEntrySetReadOnly(entry, true);

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
        uiEntrySetText(entry, ip_address_text);
    }

    { // Initial page
        auto page_box = uiNewHorizontalBox();
        uiBoxAppend(main_box, uiControl(page_box), false);
        uiBoxSetPadded(page_box, true);

        auto create_button = uiNewButton("Create");
        uiBoxAppend(page_box, uiControl(create_button), false);
        uiButtonOnClicked(create_button, on_create_page_button_pressed, (void*)&context);

        auto connect_button = uiNewButton("Connect");
        uiBoxAppend(page_box, uiControl(connect_button), false);
        uiButtonOnClicked(connect_button, on_connect_page_button_pressed, (void*)&context);

        context.initial_page_box = page_box;
        context.current_page = Page::Initial;
    }

    { // Create page
        auto page_box = uiNewVerticalBox();
        uiBoxAppend(main_box, uiControl(page_box), false);
        uiBoxSetPadded(page_box, true);
        uiControlHide(uiControl(page_box));

        auto local_connection_string_label = uiNewLabel("Your connection string (send this to your peer)");
        uiBoxAppend(page_box, uiControl(local_connection_string_label), false);

        auto local_connection_string_entry = uiNewEntry();
        uiBoxAppend(page_box, uiControl(local_connection_string_entry), false);
        uiControlDisable(uiControl(local_connection_string_entry));
        uiEntrySetReadOnly(local_connection_string_entry, true);
        uiEntrySetText(local_connection_string_entry, "Loading...");

        context.create_page_local_connection_string_entry = local_connection_string_entry;

        auto remote_connection_string_label = uiNewLabel("Their connection string (your peer will send this to you)");
        uiBoxAppend(page_box, uiControl(remote_connection_string_label), false);

        auto remote_connection_string_entry = uiNewEntry();
        uiBoxAppend(page_box, uiControl(remote_connection_string_entry), false);
        uiControlDisable(uiControl(remote_connection_string_entry));

        context.create_page_remote_connection_string_entry = remote_connection_string_entry;

        auto connect_button = uiNewButton("Connect to Peer");
        uiBoxAppend(page_box, uiControl(connect_button), false);
        uiButtonOnClicked(connect_button, on_create_page_connect_button_pressed, (void*)&context);
        uiControlDisable(uiControl(connect_button));

        context.create_page_connect_button = connect_button;

        context.create_page_box = page_box;
    }

    { // connect page
        auto page_box = uiNewVerticalBox();
        uiBoxAppend(main_box, uiControl(page_box), false);
        uiBoxSetPadded(page_box, true);
        uiControlHide(uiControl(page_box));

        auto remote_connection_string_label = uiNewLabel("Their connection string (your peer will send this to you)");
        uiBoxAppend(page_box, uiControl(remote_connection_string_label), false);

        auto remote_connection_string_entry = uiNewEntry();
        uiBoxAppend(page_box, uiControl(remote_connection_string_entry), false);

        context.connect_page_remote_connection_string_entry = remote_connection_string_entry;

        auto connect_button = uiNewButton("Generate connecting string");
        uiBoxAppend(page_box, uiControl(connect_button), false);
        uiButtonOnClicked(connect_button, on_connect_page_generate_button_pressed, (void*)&context);

        auto local_connection_string_label = uiNewLabel("Your connection string (send this to your peer)");
        uiBoxAppend(page_box, uiControl(local_connection_string_label), false);

        auto local_connection_string_entry = uiNewEntry();
        uiBoxAppend(page_box, uiControl(local_connection_string_entry), false);
        uiControlDisable(uiControl(local_connection_string_entry));
        uiEntrySetReadOnly(local_connection_string_entry, true);

        context.connect_page_local_connection_string_entry = local_connection_string_entry;

        context.connect_page_generate_button = connect_button;

        context.connect_page_box = page_box;
    }

    auto error_label = uiNewLabel("");
    uiBoxAppend(main_box, uiControl(error_label), false);
    uiControlHide(uiControl(error_label));

    context.status_label = error_label;

    uiControlShow(uiControl(window));

    uiMain();

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