#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <Windows.h>
#include "juice/juice.h"
#include "wintun.h"
#define CBASE64_IMPLEMENTATION
#include "cbase64.h"

static WINTUN_ENUM_ADAPTERS_FUNC WintunEnumAdapters;
static WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter;
static WINTUN_OPEN_ADAPTER_FUNC WintunOpenAdapter;
static WINTUN_GET_ADAPTER_NAME_FUNC WintunGetAdapterName;
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

static bool readline(char *buffer, size_t buffer_size) {
    size_t character_index = 0;
    while(character_index != buffer_size - 1) {
        auto character = getc(stdin);

        if(character == -1) {
            fprintf(stderr, "ERROR: Unexpected EOF in stdin\n");

            return false;
        }

        if(character == '\r') {
            character == getc(stdin);

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
    return true;
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

int main(int argument_count, char *arguments[]) {
    auto wintun_library = LoadLibraryA("wintun.dll");

    WintunEnumAdapters = (WINTUN_ENUM_ADAPTERS_FUNC)GetProcAddress(wintun_library, "WintunEnumAdapters");
    WintunCreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC)GetProcAddress(wintun_library, "WintunCreateAdapter");
    WintunOpenAdapter = (WINTUN_OPEN_ADAPTER_FUNC)GetProcAddress(wintun_library, "WintunOpenAdapter");
    WintunGetAdapterName = (WINTUN_GET_ADAPTER_NAME_FUNC)GetProcAddress(wintun_library, "WintunGetAdapterName");
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

    const uint8_t ip_prefix[4] = { 0, 0, 64, 100 };
    const uint8_t ip_mask[4] = { 0, 0, 192, 255 };

    srand((unsigned int)time(nullptr));

    uint8_t ip_address[4];
    ip_address[0] = (uint8_t)rand();
    ip_address[1] = (uint8_t)rand();
    ip_address[2] = (uint8_t)rand();
    ip_address[3] = (uint8_t)rand();

    ip_address[0] &= ~ip_mask[0];
    ip_address[1] &= ~ip_mask[1];
    ip_address[2] &= ~ip_mask[2];
    ip_address[3] &= ~ip_mask[3];

    ip_address[0] |= ip_prefix[0];
    ip_address[1] |= ip_prefix[1];
    ip_address[2] |= ip_prefix[2];
    ip_address[3] |= ip_prefix[3];

    printf("Your IP address is %hhu.%hhu.%hhu.%hhu\n", ip_address[3], ip_address[2], ip_address[1], ip_address[0]);

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