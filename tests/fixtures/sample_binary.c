#include <stdint.h>
#include <stdio.h>

int DriverEntry(void *DriverObject, void *RegistryPath) {
    printf("DriverEntry called: %p, %p\n", DriverObject, RegistryPath);
    return 0;
}

int DispatchDeviceControl(void *DeviceObject, void *Irp) {
    printf("DispatchDeviceControl called: %p, %p\n", DeviceObject, Irp);
    return 0;
}

int main(int argc, char **argv) {
    DriverEntry(NULL, NULL);
    DispatchDeviceControl(NULL, NULL);
    return 0;
}
