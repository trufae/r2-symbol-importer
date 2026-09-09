"""
Built-in C type preludes for radare2 / TinyCC type ingestion.
Provides complete primitive types and core structs for Windows Kernel/DDK,
POSIX, and standard stdint environments.
"""

from enum import Enum
from typing import Optional


class PreludeType(str, Enum):
    AUTO = "auto"
    WINDOWS = "windows"
    POSIX = "posix"
    STDINT = "stdint"
    NONE = "none"


PRELUDE_STDINT = """/* Standard Primitive and Integer Types for TinyCC / radare2 */
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

typedef unsigned long size_t;
typedef long ssize_t;
typedef long intptr_t;
typedef unsigned long uintptr_t;

typedef unsigned char bool;
typedef unsigned char _Bool;
"""

PRELUDE_WINDOWS = """/* Windows SDK & Kernel DDK Types for TinyCC / radare2 */
typedef void VOID;
typedef void *PVOID;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef void *HANDLE;
typedef void *HMODULE;
typedef void *HINSTANCE;
typedef void *HWND;

typedef char CHAR;
typedef unsigned char UCHAR;
typedef unsigned char BYTE;
typedef unsigned char *PBYTE;
typedef unsigned char *PUCHAR;

typedef short SHORT;
typedef unsigned short USHORT;
typedef unsigned short WORD;
typedef unsigned short *PWORD;
typedef unsigned short *PUSHORT;
typedef unsigned short WCHAR;
typedef unsigned short *PWCHAR;
typedef unsigned short *PWSTR;
typedef const unsigned short *PCWSTR;
typedef char *PSTR;
typedef const char *PCSTR;

typedef int INT;
typedef unsigned int UINT;
typedef unsigned int *PUINT;
typedef long LONG;
typedef unsigned long ULONG;
typedef unsigned long *PULONG;
typedef unsigned long DWORD;
typedef unsigned long *PDWORD;
typedef unsigned long DWORD32;
typedef unsigned long long DWORD64;
typedef unsigned long long QWORD;

typedef long long LONGLONG;
typedef unsigned long long ULONGLONG;
typedef long long INT64;
typedef unsigned long long UINT64;
typedef int INT32;
typedef unsigned int UINT32;
typedef short INT16;
typedef unsigned short UINT16;
typedef signed char INT8;
typedef unsigned char UINT8;

typedef unsigned long ULONG_PTR;
typedef long LONG_PTR;
typedef unsigned long DWORD_PTR;
typedef unsigned long SIZE_T;
typedef long SSIZE_T;

typedef unsigned char BOOLEAN;
typedef int BOOL;
typedef long NTSTATUS;

struct _GUID {
    unsigned long Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char Data4[8];
};
typedef struct _GUID GUID;
typedef struct _GUID *PGUID;

struct _UNICODE_STRING {
    unsigned short Length;
    unsigned short MaximumLength;
    unsigned short *Buffer;
};
typedef struct _UNICODE_STRING UNICODE_STRING;
typedef struct _UNICODE_STRING *PUNICODE_STRING;

struct _ANSI_STRING {
    unsigned short Length;
    unsigned short MaximumLength;
    char *Buffer;
};
typedef struct _ANSI_STRING ANSI_STRING;
typedef struct _ANSI_STRING *PANSI_STRING;

struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
};
typedef struct _LIST_ENTRY LIST_ENTRY;
typedef struct _LIST_ENTRY *PLIST_ENTRY;

struct _SINGLE_LIST_ENTRY {
    struct _SINGLE_LIST_ENTRY *Next;
};
typedef struct _SINGLE_LIST_ENTRY SINGLE_LIST_ENTRY;
typedef struct _SINGLE_LIST_ENTRY *PSINGLE_LIST_ENTRY;

struct _LARGE_INTEGER_PARTS {
    unsigned long LowPart;
    long HighPart;
};
union _LARGE_INTEGER {
    struct _LARGE_INTEGER_PARTS s;
    long long QuadPart;
};
typedef union _LARGE_INTEGER LARGE_INTEGER;
typedef union _LARGE_INTEGER *PLARGE_INTEGER;

struct _ULARGE_INTEGER_PARTS {
    unsigned long LowPart;
    unsigned long HighPart;
};
union _ULARGE_INTEGER {
    struct _ULARGE_INTEGER_PARTS s;
    unsigned long long QuadPart;
};
typedef union _ULARGE_INTEGER ULARGE_INTEGER;
typedef union _ULARGE_INTEGER *PULARGE_INTEGER;

struct _IO_STATUS_BLOCK {
    void *Pointer;
    unsigned long Information;
};
typedef struct _IO_STATUS_BLOCK IO_STATUS_BLOCK;
typedef struct _IO_STATUS_BLOCK *PIO_STATUS_BLOCK;

/* Opaque Driver Structures with safe stub bodies for TinyCC */
struct _DRIVER_OBJECT { void *Reserved; };
struct _DEVICE_OBJECT { void *Reserved; };
struct _IRP { void *Reserved; };
struct _FILE_OBJECT { void *Reserved; };

typedef struct _DEVICE_OBJECT *PDEVICE_OBJECT;
typedef struct _DRIVER_OBJECT *PDRIVER_OBJECT;
typedef struct _IRP *PIRP;
typedef struct _FILE_OBJECT *PFILE_OBJECT;
"""

PRELUDE_POSIX = """/* POSIX / Linux Driver Types for TinyCC / radare2 */
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

typedef unsigned long size_t;
typedef long ssize_t;
typedef long off_t;
typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef unsigned int mode_t;
typedef unsigned long dev_t;
typedef unsigned long ino_t;
typedef long time_t;
typedef long clock_t;
typedef long intptr_t;
typedef unsigned long uintptr_t;
typedef unsigned char bool;
"""


def detect_prelude_type(content: str) -> PreludeType:
    """Heuristically detects whether a header targets Windows, POSIX, or generic C."""
    windows_indicators = (
        "NTSTATUS", "DRIVER_OBJECT", "DEVICE_OBJECT", "PDEVICE_OBJECT",
        "PDRIVER_OBJECT", "UNICODE_STRING", "IRP", "PIRP", "PVOID",
        "DWORD", "ULONG", "CTL_CODE", "IO_STATUS_BLOCK", "__stdcall", "NTAPI"
    )
    posix_indicators = (
        "pid_t", "uid_t", "gid_t", "off_t", "mode_t", "dev_t",
        "time_t", "__attribute__((packed))", "ssize_t"
    )

    win_count = sum(1 for ind in windows_indicators if ind in content)
    posix_count = sum(1 for ind in posix_indicators if ind in content)

    if win_count > 0 and win_count >= posix_count:
        return PreludeType.WINDOWS
    if posix_count > 0:
        return PreludeType.POSIX
    return PreludeType.STDINT


def get_prelude(prelude_type: PreludeType = PreludeType.AUTO, sample_content: Optional[str] = None) -> str:
    """Returns the C code string for the specified or auto-detected prelude."""
    if prelude_type == PreludeType.AUTO:
        resolved = detect_prelude_type(sample_content or "")
    else:
        resolved = prelude_type

    if resolved == PreludeType.WINDOWS:
        return PRELUDE_WINDOWS
    elif resolved == PreludeType.POSIX:
        return PRELUDE_POSIX
    elif resolved == PreludeType.STDINT:
        return PRELUDE_STDINT
    elif resolved == PreludeType.NONE:
        return ""
    return PRELUDE_STDINT
