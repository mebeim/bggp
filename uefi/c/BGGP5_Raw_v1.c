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
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/Http.h>
#include <Protocol/ServiceBinding.h>

#define REQUEST_WAIT_MAX  5
#define RESPONSE_WAIT_MAX 5

static BOOLEAN gRequestCallbackComplete = FALSE;
static BOOLEAN gResponseCallbackComplete = FALSE;

// Request callback to get notified when request has been sent
VOID
EFIAPI
RequestCallback(
  IN EFI_EVENT Event,
  IN VOID *Context
  )
{
  gRequestCallbackComplete = TRUE;
}


// Response callback to get notified when response has been received
VOID
EFIAPI
ResponseCallback(
  IN EFI_EVENT Event,
  IN VOID *Context
  )
{
  gResponseCallbackComplete = TRUE;
}


EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                   Status = EFI_SUCCESS;
  EFI_HANDLE                   HttpChildHandle = NULL;
  EFI_HANDLE                   *Controllers;
  UINTN                        NControllers;
  EFI_HTTP_PROTOCOL            *HttpProtocol;
  EFI_SERVICE_BINDING_PROTOCOL *HttpServiceBinding;
  EFI_TIME                     Base, Cur;

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

  // Locate all HTTP Service Binding protocols (should be one per NIC)
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiManagedNetworkServiceBindingProtocolGuid,
                  NULL,
                  &NControllers,
                  &Controllers
                  );
  if ((EFI_ERROR (Status)) || (NControllers == 0)) {
    if (EFI_ERROR (Status)) {
      Print (L"LocateHandleBuffer for ManagedNetworkServiceBinding failed: %r\n", Status);
      goto out;
    }

    Print (L"No NICs found\n");
    Status = EFI_NOT_FOUND;
    goto out_free_controllers;
  }

  // We should technically iterate over the returned handles and check the NIC
  // name (that is e.g. how HttpDynamicCommand does it in EDK2 sources).
  // However I am lazy, so use the first one for simplicity.
  if (NControllers > 1)
    Print (L"Multiple NICs found using the first one found\n");

  // Get the ServiceBinding Protocol and create a child handle
  Status = gBS->OpenProtocol (
                  Controllers[0],
                  &gEfiHttpServiceBindingProtocolGuid,
                  (VOID **)&HttpServiceBinding,
                  ImageHandle,
                  Controllers[0],
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
                  );
  if (EFI_ERROR (Status)) {
    Print (L"OpenProtocol for HttpServiceBinding failed: %r\n", Status);
    goto out_free_controllers;
  }

  Status = HttpServiceBinding->CreateChild (HttpServiceBinding, &HttpChildHandle);
  if (EFI_ERROR (Status)) {
    Print (L"HttpServiceBinding::CreateChild failed: %r\n", Status);
    goto out_free_controllers;
  }

  // Finally get HTTP protocol
  Status = gBS->OpenProtocol (
                  HttpChildHandle,
                  &gEfiHttpProtocolGuid,
                  (VOID **)&HttpProtocol,
                  ImageHandle,
                  Controllers[0],
                  EFI_OPEN_PROTOCOL_BY_DRIVER
                  );
  if (EFI_ERROR (Status)) {
    Print (L"OpenProtocol for HttpProtocol failed: %r\n", Status);
    goto out_free_controllers;
  }

  // Config before doing requests
  Status = HttpProtocol->Configure (HttpProtocol, &HttpConfigData);
  if (EFI_ERROR (Status)) {
    Print (L"HttpProtocol::Configure failed: %r\n", Status);
    goto out_free_controllers;
  }

  // Create request callback event to get notified when request is sent
  Status = gBS->CreateEvent(
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  RequestCallback,
                  NULL,
                  &RequestToken.Event
                  );
  if (EFI_ERROR (Status)) {
    Print (L"CreateEvent for RequestCallback failed: %r\n", Status);
    goto out_free_controllers;
  }

  // Start the request
  Status = HttpProtocol->Request (HttpProtocol, &RequestToken);
  if (EFI_ERROR (Status)) {
    Print (L"HttpProtocol::Request failed: %r\n", Status);
    goto out_free_controllers;
  }

  Status = gRT->GetTime(&Base, NULL);
  if (EFI_ERROR (Status)) {
    Print(L"GetTime 1 failed: %r\n", Status);
    goto out_free_controllers;
  }

  // Wait up to REQUEST_WAIT_MAX seconds for request to be sent...
  for (UINTN Timer = 0; Timer < REQUEST_WAIT_MAX; ) {
    HttpProtocol->Poll(HttpProtocol);

    if (gRequestCallbackComplete)
      break;

    if (!EFI_ERROR (gRT->GetTime(&Cur, NULL)) && (Cur.Second != Base.Second)) {
      Base = Cur;
      ++Timer;
    }
  }

  if (!gRequestCallbackComplete) {
    Print (L"Request not sent in time, canceling...\n");

    Status = HttpProtocol->Cancel (HttpProtocol, &RequestToken);
    if (EFI_ERROR (Status))
      Print (L"HttpProtocol::Cancel for request failed: %r\n", Status);
    else
      Print (L"Request canceled\n");

    Status = EFI_TIMEOUT;
    goto out_free_controllers;
  }

  // Allocate response buffer
  Status = gBS->AllocatePool (EfiBootServicesData, 0x1000, (VOID **)&ResponseMessage.Body);
  if (EFI_ERROR(Status)) {
    Print(L"AllocatePool for response body failed: %r\n", Status);
    goto out_free_controllers;
  }

  // Create response callback event to get notified when response is received
  Status = gBS->CreateEvent(
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  ResponseCallback,
                  NULL,
                  &ResponseToken.Event
                  );
  if (EFI_ERROR (Status)) {
    Print (L"CreateEvent for ResponseCallback failed: %r\n", Status);
    goto out_free_controllers;
  }

  // Ask for response
  Status = HttpProtocol->Response (HttpProtocol, &ResponseToken);
  if (EFI_ERROR (Status)) {
    Print (L"HttpProtocol::Response failed: %r\n", Status);
    goto out_free_response;
  }

  Status = gRT->GetTime(&Base, NULL);
  if (EFI_ERROR (Status)) {
    Print(L"GetTime 2 failed: %r\n", Status);
    goto out_free_response;
  }

  // Wait up to RESPONSE_WAIT_MAX seconds for response...
  for (UINTN Timer = 0; Timer < RESPONSE_WAIT_MAX; ) {
    HttpProtocol->Poll(HttpProtocol);

    if (gResponseCallbackComplete)
      break;

    if (!EFI_ERROR (gRT->GetTime(&Cur, NULL)) && (Cur.Second != Base.Second)) {
      Base = Cur;
      ++Timer;
    }
  }

  if (!gResponseCallbackComplete) {
    Print (L"Response not received in time, canceling...\n");

    Status = HttpProtocol->Cancel (HttpProtocol, &ResponseToken);
    if (EFI_ERROR (Status))
      Print (L"HttpProtocol::Cancel for response failed: %r\n", Status);
    else
      Print (L"Request canceled\n");

    Status = EFI_TIMEOUT;
    goto out_free_response;
  }

  Print (L"%.*a", ResponseMessage.BodyLength, ResponseMessage.Body);

out_free_response:
  gBS->FreePool (ResponseMessage.Body);
out_free_controllers:
  if (Controllers != NULL)
    gBS->FreePool (Controllers);
out:
  return Status;
}
