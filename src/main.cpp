#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <Windows.h>
#include "juice/juice.h"
#include "wintun.h"

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
};

static void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
    auto parameters = (JuiceParameters*)user_ptr;

    auto packet = WintunAllocateSendPacket(parameters->wintun_session, (DWORD)size);

    memcpy(packet, data, size);

    WintunSendPacket(parameters->wintun_session, packet);
}

static bool readline(char *buffer, size_t buffer_size) {
    assert(buffer_size >= 2);

    size_t character_index = 0;
    while(character_index != buffer_size - 2) {
        auto character = getc(stdin);

        if(character == -1) {
            return false;
        }

        buffer[character_index] = (char)character;

        character_index += 1;

        if(character == '\n') {
            break;
        }
    }

    buffer[character_index] = '\n';
    buffer[character_index + 1] = '\0';

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

int main(int argument_count, char *arguments[]) {
#ifndef NDEBUG
    juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);
#endif

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
        const static GUID guid { 0xca88f39e, 0x7b30, 0x4ac1, { 0x8a, 0x8, 0xef, 0xf4, 0x22, 0xc, 0x13, 0x3a } };
        wintun_adapter = WintunCreateAdapter(pool_name, L"P2P VPN Adapter", &guid, nullptr);
    }

    auto wintun_session = WintunStartSession(wintun_adapter, 0x400000);

    JuiceParameters parameters;
    parameters.wintun_session = wintun_session;

    juice_config_t config {};
    config.stun_server_host = "stun.stunprotocol.org";
    config.stun_server_port = 3478;

    config.user_ptr = (void*)&parameters;

    config.cb_recv = on_recv;

    auto agent = juice_create(&config);

    char sdp[JUICE_MAX_SDP_STRING_LEN];
    juice_get_local_description(agent, sdp, JUICE_MAX_SDP_STRING_LEN);

    printf("Local SDP:\n%s\n", sdp);

    char remote_sdp[JUICE_MAX_SDP_STRING_LEN] = "";

    printf("Please enter remote SDP:\n");

    while(true) {
        char line[JUICE_MAX_SDP_STRING_LEN];
        if(!readline(line, JUICE_MAX_SDP_STRING_LEN)) {
            fprintf(stderr, "ERROR: Unexpected EOF in stdin\n");

            return 1;
        }

        size_t character_index = 0;
        while(character_index != JUICE_MAX_ADDRESS_STRING_LEN - 1) {
            auto character = getc(stdin);

            if(character == -1) {
                fprintf(stderr, "ERROR: Unexpected EOF in stdin\n");

                return 1;
            }

            line[character_index] = (char)character;

            character_index += 1;

            if(character == '\n') {
                break;
            }
        }

        line[character_index] = '\0';

        if(strcmp(line, "\n") == 0) {
            break;
        }

        strcat_s(remote_sdp, line);
    }

    juice_set_remote_description(agent, remote_sdp);

    juice_gather_candidates(agent);

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