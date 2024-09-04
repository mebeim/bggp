/** @file
  BGGP5 UEFI Application - https://binary.golf/5/

  Downloads and displays the contents of the file at https://binary.golf/5/5
  using raw EFI HTTP protocol.

  Copyright (c) 2024, Marco Bonelli. All rights reserved.
  SPDX-License-Identifier: MIT

**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Http.h>
#include <Protocol/ServiceBinding.h>

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                   Status = EFI_SUCCESS;
  EFI_HANDLE                   HttpChildHandle = NULL;
  EFI_HTTP_PROTOCOL            *HttpProtocol;
  EFI_SERVICE_BINDING_PROTOCOL *HttpServiceBinding;

  EFI_HTTPv4_ACCESS_POINT Http4AccessPoint = {
    .UseDefaultAddress = TRUE
  };

  EFI_HTTP_CONFIG_DATA HttpConfigData = {
    .HttpVersion          = HttpVersion11,
    .LocalAddressIsIPv6   = FALSE,
    .AccessPoint.IPv4Node = &Http4AccessPoint
  };

  EFI_HTTP_REQUEST_DATA RequestData = {
    .Method = HttpMethodGet,
    .Url    = L"https://binary.golf/5/5"
  };

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

  // Locate all HTTP Service Binding protocol
  Status = gBS->LocateProtocol (
                  &gEfiHttpServiceBindingProtocolGuid,
                  NULL,
                  (VOID **)&HttpServiceBinding
                  );
  if (EFI_ERROR(Status)) {
    Print(L"LocateProtocol for HttpServiceBinding failed: %r\n", Status);
    goto out;
  }

  // Create child handle
  Status = HttpServiceBinding->CreateChild (HttpServiceBinding, &HttpChildHandle);
  if (EFI_ERROR(Status)) {
    Print (L"HttpServiceBinding::CreateChild failed: %r\n", Status);
    goto out;
  }

  // Get HttpProtocol with child handle
  Status = gBS->HandleProtocol (HttpChildHandle, &gEfiHttpProtocolGuid, (VOID **)&HttpProtocol);
  if (EFI_ERROR(Status)) {
    Print(L"HandleProtocol for HttpProtocol failed\n");
    goto out_destroy_child_handle;
  }

  // Config before doing request
  Status = HttpProtocol->Configure (HttpProtocol, &HttpConfigData);
  if (EFI_ERROR (Status)) {
    Print (L"HttpProtocol::Configure failed: %r\n", Status);
    goto out_destroy_child_handle;
  }

  // Start the request
  Status = HttpProtocol->Request (HttpProtocol, &RequestToken);
  if (EFI_ERROR (Status)) {
    Print (L"HttpProtocol::Request failed: %r\n", Status);
    goto out_destroy_child_handle;
  }

  // Allocate response buffer
  Status = gBS->AllocatePool (EfiBootServicesData, 0x1000, (VOID **)&ResponseMessage.Body);
  if (EFI_ERROR (Status)) {
    Print(L"AllocatePool for response body failed: %r\n", Status);
    goto out_destroy_child_handle;
  }

  // Ask for response synchronously
  Status = HttpProtocol->Response (HttpProtocol, &ResponseToken);
  if (EFI_ERROR (Status)) {
    Print (L"HttpProtocol::Response failed: %r\n", Status);
    goto out_free_response;
  }

  Print (L"%.*a", ResponseMessage.BodyLength, ResponseMessage.Body);

out_free_response:
  gBS->FreePool (ResponseMessage.Body);
out_destroy_child_handle:
  HttpServiceBinding->DestroyChild (HttpServiceBinding, HttpChildHandle);
out:
  return Status;
}
