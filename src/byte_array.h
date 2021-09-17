#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>

struct ByteArray {
    size_t length;
    uint8_t *data;

    inline uint8_t &operator[](size_t index) {
        assert(index < length);

        return data[index];
    }
};

static inline ByteArray make_array(size_t length, uint8_t *data) {
    return ByteArray {
        length,
        data
    };
}

static inline void copy_array(ByteArray destination, size_t destination_offset, ByteArray source) {
    assert(destination_offset + source.length <= destination.length);

    memcpy(&destination.data[destination_offset], source.data, source.length);
}

static inline void zero_array(ByteArray array) {
    memset(array.data, 0, array.length);
}

static inline ByteArray subarray(ByteArray array, size_t offset, size_t length) {
    assert(offset + length <= array.length);

    return {
        length,
        &array.data[offset]
    };
}

static inline ByteArray subarray(ByteArray array, size_t offset) {
    assert(offset <= array.length);

    return {
        array.length - offset,
        &array.data[offset]
    };
}

static inline uint8_t* get_c_array(ByteArray array, size_t expected_length) {
    assert(array.length == expected_length);

    return array.data;
}

static inline void print_array(ByteArray array) {
    for(size_t i = 0; i < array.length; i += 1) {
        printf("%.2hhX", array.data[i]);
    }
}

#define array_data_length(array) array.data, array.length

template <size_t L>
struct StaticByteArray {
    static_assert(L > 0);

    const size_t length = L;

    uint8_t data[L];

    inline uint8_t &operator[](size_t index) {
        assert(index < length);

        return data[index];
    }

    inline operator ByteArray() {
        return {
            L,
            data
        };
    }
};

struct OwnedByteArray : ByteArray {};

static inline OwnedByteArray allocate_array(size_t length) {
    auto data = (uint8_t*)malloc(length);

    return {
        length,
        data
    };
}

static inline void free_array(OwnedByteArray array) {
    free(array.data);
}