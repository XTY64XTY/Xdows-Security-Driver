/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_XdowsSecurityDriver,
    0xec5db072,0x8119,0x4d65,0xa7,0xae,0x67,0xd7,0xf3,0x10,0x05,0xe1);
// {ec5db072-8119-4d65-a7ae-67d7f31005e1}
