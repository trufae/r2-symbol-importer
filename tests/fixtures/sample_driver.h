#ifndef _SAMPLE_DRIVER_H_
#define _SAMPLE_DRIVER_H_

#define IOCTL_DEVICE_BASE               0x8000
#define IOCTL_SAMPLE_READ_DATA          CTL_CODE(IOCTL_DEVICE_BASE, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_SAMPLE_WRITE_DATA         CTL_CODE(IOCTL_DEVICE_BASE, 0x801, METHOD_IN_DIRECT, FILE_WRITE_ACCESS)
#define IOCTL_SAMPLE_RESET              CTL_CODE(IOCTL_DEVICE_BASE, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)

#define DRIVER_FLAG_ACTIVE              (1 << 0)
#define DRIVER_FLAG_INITIALIZED         (1 << 1)
#define DRIVER_FLAG_SUSPENDED           (1 << 2)
#define DRIVER_FULL_MASK                (DRIVER_FLAG_ACTIVE | DRIVER_FLAG_INITIALIZED | DRIVER_FLAG_SUSPENDED)
#define MAX_PACKET_SIZE                 (4 * 1024)

typedef struct _PACKET_HEADER {
    DWORD SequenceNumber;
    DWORD PayloadLength;
    BYTE  Flags;
} PACKET_HEADER, *PPACKET_HEADER;

typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT  DeviceObject;
    DWORD           StateFlags;
    PACKET_HEADER   LastPacket;
    PVOID           Buffer;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

_Must_inspect_result_
NTSTATUS NTAPI DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS NTAPI DispatchCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

NTSTATUS NTAPI DispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

VOID NTAPI DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
);

#endif // _SAMPLE_DRIVER_H_
