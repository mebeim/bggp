/** @file
  BGGP5 UEFI Application - https://binary.golf/5/

  Downloads and displays the contents of the file at https://binary.golf/5/5
  using the EDK II HttpIoLib library.

  Copyright (c) 2024, Marco Bonelli. All rights reserved.
  SPDX-License-Identifier: MIT

**/

#include <Uefi.h>
#include <Library/HttpIoLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

// HttpIoCreateIo callback for debugging purposes
//
// EFI_STATUS
// EFIAPI
// Callback (
//   IN  HTTP_IO_CALLBACK_EVENT EventType,
//   IN  EFI_HTTP_MESSAGE       *Message,
//   IN  VOID                   *Context
//   )
// {
//   if (EventType == HttpIoRequest) {
//     Print (L"Callback on HttpIoRequest: BodyLength = %lu\n", Message->BodyLength);
//   } else if (EventType == HttpIoResponse) {
//     Print (L"Callback on HttpIoResponse: BodyLength = %lu\n", Message->BodyLength);
//   } else {
//     Print (L"Callback on unknown event type: %d\n", EventType);
//     return EFI_SUCCESS;
//   }
//
//   if (Message->HeaderCount == 0)
//     Print (L"No headers\n");
//   else
//     Print (L"%lu headers\n", Message->HeaderCount);
//
//   // Somehow prints garbage...
//   // for (UINTN i = 0; i < Message->HeaderCount; i++)
//   //   Print (L" - Headers[%lu] = %a: %a", i, Message->Headers[i].FieldName, Message->Headers[i].FieldValue);
//
//   return EFI_SUCCESS;
// }

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{

  EFI_STATUS            Status = EFI_SUCCESS;
  EFI_HANDLE            *Controllers;
  UINTN                 NControllers;
  HTTP_IO               HttpIo;
  HTTP_IO_RESPONSE_DATA ResponseData;

  HTTP_IO_CONFIG_DATA ConfigData = {
    .Config4.HttpVersion       = HttpVersion11,
    .Config4.UseDefaultAddress = TRUE,
  };

  EFI_HTTP_REQUEST_DATA RequestData = {
    .Method = HttpMethodGet,
    .Url    = L"https://binary.golf/5/5",
  };

  EFI_HTTP_HEADER RequestHeaders[] = {
    { "Host", "binary.golf" },
  };

  // Print (L"BGGP5 UefiMain: hello!\n");

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

  Status = HttpIoCreateIo (
              ImageHandle,
              Controllers[0],
              IP_VERSION_4,
              &ConfigData,
              NULL,
              NULL,
              &HttpIo
              );
  if (EFI_ERROR(Status)) {
    Print (L"HttpIoCreateIo failed: %r\n", Status);
    goto out_free_controllers;
  }

  Status = HttpIoSendRequest (
              &HttpIo,
              &RequestData,
              sizeof(RequestHeaders) / sizeof(*RequestHeaders),
              RequestHeaders,
              0,
              NULL
              );
  if (EFI_ERROR(Status)) {
    Print (L"HttpIoSendRequest failed: %r\n", Status);
    goto out_free_httpio;
  }

  ResponseData.BodyLength = 0x1000;
  ResponseData.Body = AllocatePool (ResponseData.BodyLength);
  if (ResponseData.Body == NULL) {
    Print (L"AllocatePool failed: %r\n", Status);
    Status = EFI_OUT_OF_RESOURCES;
    goto out_free_httpio;
  }

  Status = HttpIoRecvResponse (&HttpIo, TRUE, &ResponseData);
  if (EFI_ERROR (Status)) {
    Print (L"HttpIoRecvResponse failed: %r\n", Status);
    goto out_free_response;
  }

  // Pretty dumb but HTTP_STATUS_200_OK == 3... it's an enum, not the real HTTP
  // status code. LOL.
  if (ResponseData.Response.StatusCode != HTTP_STATUS_200_OK) {
    Print (L"Bad response status: %d\n", ResponseData.Response.StatusCode);
    Status = EFI_ABORTED;
    goto out_free_response;
  }

  // Print (L"Response length: %ld\n", ResponseData.BodyLength);
  Print (L"%.*a", ResponseData.BodyLength, ResponseData.Body);

  // Print (L"BGGP5 UefiMain: goodbye!\n");

out_free_response:
  FreePool (ResponseData.Body);
out_free_httpio:
  HttpIoDestroyIo (&HttpIo);
out_free_controllers:
  if (Controllers != NULL)
    FreePool (Controllers);
out:
  return Status;
}
