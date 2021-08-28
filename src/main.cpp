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

struct JuiceParameters {
    WINTUN_SESSION_HANDLE wintun_session;

    HANDLE gathering_done_event;
};

static void on_gathering_done(juice_agent_t *agent, void *user_ptr) {
    auto parameters = (JuiceParameters*)user_ptr;

    SetEvent(parameters->gathering_done_event);
}

static void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
    auto parameters = (JuiceParameters*)user_ptr;

    auto packet = WintunAllocateSendPacket(parameters->wintun_session, (DWORD)size);

    memcpy(packet, data, size);

    WintunSendPacket(parameters->wintun_session, packet);
}

static void readline(char *buffer, size_t buffer_size) {
    size_t character_index = 0;
    while(character_index != buffer_size - 1) {
        auto character = getc(stdin);

        if(character == -1) {
            fprintf(stderr, "\nERROR: Unexpected EOF in stdin\n");

            exit(1);
        }

        if(character == '\r') {
            character = getc(stdin);

            if(character != '\n') {
                ungetc(character, stdin);
            }
        } else if(character == '\n') {
            break;
        }

        buffer[character_index] = (char)character;

        character_index += 1;
    }

    buffer[character_index] = '\0';
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

static void base64_encode_string(const char *string, char *buffer) {
    cbase64_encodestate encode_state;
    cbase64_init_encodestate(&encode_state);

    auto length_written = (size_t)cbase64_encode_block(
        (unsigned char*)string,
        (unsigned int)strlen(string),
        buffer,
        &encode_state
    );

    length_written += cbase64_encode_blockend(&(buffer[length_written]), &encode_state);

    buffer[length_written] = '\0';
}

static void base64_decode_string(const char *base64_string, char *buffer) {
    cbase64_decodestate decode_state;
    cbase64_init_decodestate(&decode_state);

    auto length_written = (size_t)cbase64_decode_block(
        base64_string,
        (unsigned int)strlen(base64_string),
        (unsigned char*)buffer,
        &decode_state
    );

    buffer[length_written] = '\0';
}

const static size_t max_connection_string_length = 4 * ((JUICE_MAX_SDP_STRING_LEN - 1) / 3) + (((JUICE_MAX_SDP_STRING_LEN - 1) % 3 != 0) ? 4 : 0);

static void acquire_local_connection_string(juice_agent_t *agent, JuiceParameters juice_parameters) {
    juice_gather_candidates(agent);

    WaitForSingleObject(juice_parameters.gathering_done_event, INFINITE);

    char local_description[JUICE_MAX_SDP_STRING_LEN];
    juice_get_local_description(agent, local_description, JUICE_MAX_SDP_STRING_LEN);

    char local_description_base64[max_connection_string_length + 1];
    base64_encode_string(local_description, local_description_base64);

    printf("Your local connection string: %s\n", local_description_base64);
}

static void acquire_remote_connection_string(juice_agent_t *agent) {
    char remote_description_base64[max_connection_string_length + 1];

    printf("Please enter remote connection string: ");
    readline(remote_description_base64, max_connection_string_length + 1);

    char remote_description[JUICE_MAX_SDP_STRING_LEN];
    base64_decode_string(remote_description_base64, remote_description);

    juice_set_remote_description(agent, remote_description);
}

#define IP_CONSTANT(a, b, c, d) ((uint32_t)d | (uint32_t)c << 8 | (uint32_t)b << 16 | (uint32_t)a << 24)

int main(int argument_count, char *arguments[]) {
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
    const uint32_t ip_subnet_mask = ~0 << (32 - ip_subnet_length); // Crazy bit stuff to calculate subnet mask

    srand((unsigned int)time(nullptr));

    uint32_t ip_address;

    ip_address = (uint32_t)rand();

    ip_address &= ~ip_subnet_mask;

    ip_address |= ip_subnet_prefix;

    printf(
        "Your IP address is %hhu.%hhu.%hhu.%hhu\n",
        (uint8_t)(ip_address >> 24),
        (uint8_t)(ip_address >> 16),
        (uint8_t)(ip_address >> 8),
        (uint8_t)ip_address
    );

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

    JuiceParameters juice_parameters;
    juice_parameters.wintun_session = wintun_session;
    juice_parameters.gathering_done_event = CreateEventA(nullptr, FALSE, FALSE, "gathering_done");

    juice_config_t config {};
    config.stun_server_host = "stun.stunprotocol.org";
    config.stun_server_port = 3478;

    config.user_ptr = (void*)&juice_parameters;

    config.cb_gathering_done = on_gathering_done;
    config.cb_recv = on_recv;

    auto agent = juice_create(&config);

    char main_option[128];

    printf("create: Create a network\n");
    printf("connect: Connect to an existing network\n");
    printf("Please choose an option: ");

    readline(main_option, 128);

    if(strcmp(main_option, "create") == 0) {
        acquire_local_connection_string(agent, juice_parameters);

        acquire_remote_connection_string(agent);
    } else if(strcmp(main_option, "connect") == 0) {
        acquire_remote_connection_string(agent);

        acquire_local_connection_string(agent, juice_parameters);
    } else {
        fprintf(stderr, "ERROR: Unknown option '%s'\n", main_option);

        return 1;
    }

    auto wintun_wait_handle = WintunGetReadWaitEvent(wintun_session);

    while(true) {
        DWORD packet_size;
        auto packet = WintunReceivePacket(wintun_session, &packet_size);

        if(packet != nullptr) {
            if(juice_get_state(agent) == JUICE_STATE_COMPLETED) {
                juice_send(agent, (const char*)packet, packet_size);
            }

            WintunReleaseReceivePacket(wintun_session, packet);
        } else {
            WaitForSingleObject(wintun_wait_handle, INFINITE);
        }
    }

    return 0;
}