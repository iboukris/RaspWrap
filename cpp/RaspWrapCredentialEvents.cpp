//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// This is our implementation of ICredentialProviderCredentialEvents (ICPCE).
// Most credential provider authors will not need to implement this interface,
// but a credential provider that wraps another (as this sample does) must.
// The wrapped credential will pass its "this" pointer into any calls to ICPCE,
// but LogonUI will not recognize the wrapped "this" pointer as a valid credential.
// Our implementation translates from the wrapped "this" pointer to the wrapper "this".

#include <unknwn.h>

#include "RaspWrapCredentialEvents.h"

HRESULT RaspWrapCredentialEvents::SetFieldState(__in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID, __in CREDENTIAL_PROVIDER_FIELD_STATE cpfs)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldState(_pWrapperCredential, dwFieldID, cpfs);
    }

    log("RaspWrapCredentialEvents::SetFieldState(): this(%p): dwFieldID=%d cpfs=%d\n", this, dwFieldID, cpfs);

    return hr;
}

HRESULT RaspWrapCredentialEvents::SetFieldInteractiveState(__in ICredentialProviderCredential* pcpc,
    __in DWORD dwFieldID, __in CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    log("RaspWrapCredentialEvents::SetFieldInteractiveState(): this(%p): dwFieldID=%d cpfis=%d\n", this, dwFieldID, cpfis);


    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldInteractiveState(_pWrapperCredential, dwFieldID, cpfis);
    }

    return hr;
}

HRESULT RaspWrapCredentialEvents::SetFieldString(__in ICredentialProviderCredential* pcpc,
    __in DWORD dwFieldID, __in PCWSTR psz)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    log("RaspWrapCredentialEvents::SetFieldString(): this(%p): dwFieldID=%d \n", this, dwFieldID);
    log("RaspWrapCredentialEvents::SetFieldString(): %S\n", psz);

    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldString(_pWrapperCredential, dwFieldID, psz);
    }

    /* Hide the UseSSO checkbox if we are already connected */
    if (SUCCEEDED(hr) && dwFieldID == RASP_CONNECTION_STATUS_AT) {
        bool connected = !wcscmp(psz, L"Connected");
        hr = SetFieldState(pcpc, _dwSSOFieldID, connected ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE);
    }

    return hr;
}

HRESULT RaspWrapCredentialEvents::SetFieldBitmap(__in ICredentialProviderCredential* pcpc,
    __in DWORD dwFieldID, __in HBITMAP hbmp)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    log("RaspWrapCredentialEvents::SetFieldBitmap(): this(%p): dwFieldID=%d \n", this, dwFieldID);


    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldBitmap(_pWrapperCredential, dwFieldID, hbmp);
    }

    return hr;
}

HRESULT RaspWrapCredentialEvents::SetFieldCheckbox(__in ICredentialProviderCredential* pcpc,
    __in DWORD dwFieldID, __in BOOL bChecked, __in PCWSTR pszLabel)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    log("RaspWrapCredentialEvents::SetFieldCheckbox(): this(%p): dwFieldID=%d \n", this, dwFieldID);


    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldCheckbox(_pWrapperCredential, dwFieldID, bChecked, pszLabel);
    }

    return hr;
}

HRESULT RaspWrapCredentialEvents::SetFieldComboBoxSelectedItem(__in ICredentialProviderCredential* pcpc,
    __in DWORD dwFieldID, __in DWORD dwSelectedItem)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    log("RaspWrapCredentialEvents::SetFieldComboBoxSelectedItem(): this(%p): dwFieldID=%d \n", this, dwFieldID);


    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldComboBoxSelectedItem(_pWrapperCredential, dwFieldID, dwSelectedItem);
    }

    return hr;
}

HRESULT RaspWrapCredentialEvents::DeleteFieldComboBoxItem(__in ICredentialProviderCredential* pcpc,
    __in DWORD dwFieldID, __in DWORD dwItem)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    log("RaspWrapCredentialEvents::DeleteFieldComboBoxItem(): this(%p): dwFieldID=%d \n", this, dwFieldID);

    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->DeleteFieldComboBoxItem(_pWrapperCredential, dwFieldID, dwItem);
    }

    return hr;
}

HRESULT RaspWrapCredentialEvents::AppendFieldComboBoxItem(__in ICredentialProviderCredential* pcpc,
    __in DWORD dwFieldID, __in PCWSTR pszItem)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    log("RaspWrapCredentialEvents::AppendFieldComboBoxItem(): this(%p): dwFieldID=%d \n", this, dwFieldID);


    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->AppendFieldComboBoxItem(_pWrapperCredential, dwFieldID, pszItem);
    }

    return hr;
}

HRESULT RaspWrapCredentialEvents::SetFieldSubmitButton(__in ICredentialProviderCredential* pcpc,
    __in DWORD dwFieldID, __in DWORD dwAdjacentTo)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    log("RaspWrapCredentialEvents::SetFieldSubmitButton(): this(%p): dwFieldID=%d \n", this, dwFieldID);

    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldSubmitButton(_pWrapperCredential, dwFieldID, dwAdjacentTo);
    }

    return hr;
}

HRESULT RaspWrapCredentialEvents::OnCreatingWindow(__out HWND* phwndOwner)
{
    HRESULT hr = E_FAIL;

    log("RaspWrapCredentialEvents::OnCreatingWindow(): this(%p)\n", this);

    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->OnCreatingWindow(phwndOwner);
    }

    return hr;
}

RaspWrapCredentialEvents::RaspWrapCredentialEvents() :
    _cRef(1), _pWrapperCredential(NULL), _pEvents(NULL), _dwSSOFieldID(0)
{
    log("RaspWrapCredentialEvents::RaspWrapCredentialEvents(): this(%p)\n", this);
}

//
// Save a copy of LogonUI's ICredentialProviderCredentialEvents pointer for doing callbacks
// and the "this" pointer of the wrapper credential to specify events as coming from.
//
// Pointers are saved as weak references (ie, without a reference count) to avoid circular
// references.  (For instance, The wrapper credential has a reference on the wrapped credential
// and the wrapped credential should take a reference on this object.  If we had a reference
// on the wrapper credential, there would be a cycle.)  The wrapper credential must manage
// the lifetime of our weak references through calls to Initialize and Uninitialize to
// prevent our weak references from becoming invalid.
//
void RaspWrapCredentialEvents::Initialize(__in ICredentialProviderCredential* pWrapperCredential,
    __in ICredentialProviderCredentialEvents* pEvents, DWORD dwSSOFieldID)
{
    _pWrapperCredential = pWrapperCredential;
    _pEvents = pEvents;
    _dwSSOFieldID = dwSSOFieldID;
}

//
// Erase our weak references on the wrapper credential and LogonUI's
// ICredentialProviderCredentialEvents pointer.
//
void RaspWrapCredentialEvents::Uninitialize()
{
    _pWrapperCredential = NULL;
    _pEvents = NULL;
}
