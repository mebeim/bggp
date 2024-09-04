/** @file
  BGGP5 UEFI Application - https://binary.golf/5/

  Downloads and displays the contents of the file at https://binary.golf/5/5
  using raw EFI HTTP protocol.

  Does not use any fancy library funcs, does not perform any error checking nor
  cleanup. Just the bare minimum to get the job done.

  Copyright (c) 2024, Marco Bonelli. All rights reserved.
  SPDX-License-Identifier: MIT

**/

#include <Uefi.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Protocol/Http.h>
#include <Protocol/ServiceBinding.h>

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_HANDLE                      HttpChildHandle = NULL;
  EFI_HTTP_PROTOCOL               *HttpProtocol;
  EFI_SERVICE_BINDING_PROTOCOL    *HttpServiceBinding;
  EFI_BOOT_SERVICES               *BS = SystemTable->BootServices;
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut = SystemTable->ConOut;

  EFI_HTTPv4_ACCESS_POINT Http4AccessPoint;
  Http4AccessPoint.UseDefaultAddress    = TRUE;
  Http4AccessPoint.LocalAddress.Addr[0] = 0;
  Http4AccessPoint.LocalAddress.Addr[1] = 0;
  Http4AccessPoint.LocalAddress.Addr[2] = 0;
  Http4AccessPoint.LocalAddress.Addr[3] = 0;
  Http4AccessPoint.LocalPort            = 0;

  EFI_HTTP_CONFIG_DATA HttpConfigData;
  HttpConfigData.HttpVersion          = HttpVersion11;
  HttpConfigData.LocalAddressIsIPv6   = FALSE;
  HttpConfigData.AccessPoint.IPv4Node = &Http4AccessPoint;

  EFI_HTTP_REQUEST_DATA RequestData;
  RequestData.Method = HttpMethodGet;
  RequestData.Url    = L"https://binary.golf/5/5";

  EFI_HTTP_HEADER RequestHeaders[] = {
    { "Host", "binary.golf" }
  };

  EFI_HTTP_MESSAGE RequestMessage = {
    .Data.Request = &RequestData,
    .HeaderCount  = sizeof(RequestHeaders) / sizeof(*RequestHeaders),
    .Headers      = RequestHeaders,
    .BodyLength   = 0,
    .Body         = NULL
  };

  EFI_HTTP_TOKEN RequestToken = {
    .Status  = EFI_SUCCESS,
    .Message = &RequestMessage
  };

  EFI_HTTP_RESPONSE_DATA ResponseData = {
    .StatusCode = HTTP_STATUS_UNSUPPORTED_STATUS,
  };

  EFI_HTTP_MESSAGE ResponseMessage = {
    .Data.Response = &ResponseData,
    .BodyLength    = 0x1000,
  };

  EFI_HTTP_TOKEN ResponseToken = {
    .Status  = EFI_SUCCESS,
    .Message = &ResponseMessage
  };

  // Locate first interface for HTTP Service Binding protocol (i.e. first NIC)
  BS->LocateProtocol (&gEfiHttpServiceBindingProtocolGuid, NULL, (VOID **)&HttpServiceBinding);
  // Create child handle
  HttpServiceBinding->CreateChild (HttpServiceBinding, &HttpChildHandle);
  // Get HttpProtocol through child handle
  BS->HandleProtocol (HttpChildHandle, &gEfiHttpProtocolGuid, (VOID **)&HttpProtocol);
  // Config before doing request
  HttpProtocol->Configure (HttpProtocol, &HttpConfigData);
  // Start the request
  HttpProtocol->Request (HttpProtocol, &RequestToken);

  // Allocate response buffer. Even though intuitively we could save code by
  // defining the response buffer on the stack, we actually do not and the final
  // size increases. Unsure why. Must be some compiler/PE shenanigans.
  BS->AllocatePool (EfiBootServicesData, 0x1000, (VOID **)&ResponseMessage.Body);
  *(UINT8 *)ResponseMessage.Body = 0;

  // Ask for response synchronously
  HttpProtocol->Response (HttpProtocol, &ResponseToken);

  CHAR16 tmp[2];
  tmp[1] = 0;

  // Print response one byte at a time converting to UTF-16
  for (UINTN i = 0; i < ResponseMessage.BodyLength; i++) {
    tmp[0] = (CHAR16)((CHAR8 *)ResponseMessage.Body)[i];
    ConOut->OutputString (ConOut, tmp);
  }

  return EFI_SUCCESS;
}
