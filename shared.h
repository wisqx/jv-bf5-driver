// language: C, file: shared.h
#pragma once
#include <cstdint>

#define JV_DEVICE_NAME L"\\Device\\JvBf5_9f3a"
#define JV_SYM_NAME    L"\\??\\JvBf5_9f3a"

#define IOCTL_JV_READ      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_JV_GET_BASE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
struct JV_PACKET {
    uint32_t pid;
    uint32_t pad;
    uint64_t va;
    uint64_t size;
};
#pragma pack(pop)