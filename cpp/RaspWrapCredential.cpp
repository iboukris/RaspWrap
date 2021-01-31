//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include <new>

#include "RaspWrapCredential.h"
#include "RaspWrapCredentialEvents.h"
#include "guid.h"

RaspWrapCredential::RaspWrapCredential():
    _cRef(1), _bUseSSOChecked(false)
{
    DllAddRef();

    log("RaspWrapCredential::RaspWrapCredential(): this(%p)\n", this);

    _pWrappedCredential = NULL;
    _pWrappedCredentialEvents = NULL;
    _pCredProvCredentialEvents = NULL;
    _dwWrappedDescriptorCount = 0;
}

RaspWrapCredential::~RaspWrapCredential()
{
    log("RaspWrapCredential::~RaspWrapCredential(): this(%p)\n", this);

    _CleanupEvents();

    if (_pWrappedCredential)
    {
        _pWrappedCredential->Release();
    }
    DllRelease();
}

// Initializes one credential with the field information passed in. We also keep track
// of our wrapped credential and how many fields it has.
HRESULT RaspWrapCredential::Initialize(
    __in IConnectableCredentialProviderCredential *pWrappedCredential,
    __in DWORD dwWrappedDescriptorCount)
{
    HRESULT hr = S_OK;

    log("RaspWrapCredential::Initialize(): this(%p)\n", this);

    // Grab the credential we're wrapping for future reference.
    if (_pWrappedCredential != NULL)
    {
        _pWrappedCredential->Release();
    }
    _pWrappedCredential = pWrappedCredential;
    _pWrappedCredential->AddRef();

    _dwWrappedDescriptorCount = dwWrappedDescriptorCount;

    log("RaspWrapCredential::Initialize(): this(%p): dwWrappedDescriptorCount=%d\n",
        this, dwWrappedDescriptorCount);

    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of
// anything. We'll also provide it to the wrapped credential.
HRESULT RaspWrapCredential::Advise(
    __in ICredentialProviderCredentialEvents* pcpce
    )
{
    HRESULT hr = S_OK;

    log("RaspWrapCredential::Advise(): this(%p)\n", this);

    _CleanupEvents();

    // We keep a strong reference on the real ICredentialProviderCredentialEvents
    // to ensure that the weak reference held by the RaspWrapCredentialEvents is valid.
    _pCredProvCredentialEvents = pcpce;
    _pCredProvCredentialEvents->AddRef();

    _pWrappedCredentialEvents = new (std::nothrow) RaspWrapCredentialEvents();

    if (_pWrappedCredentialEvents != NULL)
    {
        _pWrappedCredentialEvents->Initialize(this, pcpce, _dwWrappedDescriptorCount);

        if (_pWrappedCredential != NULL)
        {
            hr = _pWrappedCredential->Advise(_pWrappedCredentialEvents);
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}

// LogonUI calls this to tell us to release the callback.
// We'll also provide it to the wrapped credential.
HRESULT RaspWrapCredential::UnAdvise()
{
    HRESULT hr = S_OK;

    log("RaspWrapCredential::UnAdvise(): this(%p)\n", this);

    if (_pWrappedCredential != NULL)
    {
        _pWrappedCredential->UnAdvise();
    }

    _CleanupEvents();

    return hr;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. In fact, we're just going to hand it off to the
// wrapped credential in case it wants to do something.
HRESULT RaspWrapCredential::SetSelected(__out BOOL* pbAutoLogon)
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredential::SetSelected(): this(%p)\n", this);

    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->SetSelected(pbAutoLogon);
    }

    return hr;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. We'll let the wrapped credential do anything it needs.
HRESULT RaspWrapCredential::SetDeselected()
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredential::SetDeselected(): this(%p)\n", this);

    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->SetDeselected();
    }

    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information to
// display the tile. We'll check to see if it's for us or the wrapped credential, and then
// handle or route it as appropriate.
HRESULT RaspWrapCredential::GetFieldState(
    __in DWORD dwFieldID,
    __out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    __out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
    )
{
    HRESULT hr = E_UNEXPECTED;

    if (pcpfs == NULL || pcpfis == NULL)
    {
        return hr;
    }
    log("RaspWrapCredential::GetFieldState(): this(%p): dwFieldID=%d \n", this, dwFieldID);

    if (dwFieldID == _dwWrappedDescriptorCount)
    {
        *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        *pcpfis = CPFIS_NONE;
        return S_OK;
    }

    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->GetFieldState(dwFieldID, pcpfs, pcpfis);
        if (SUCCEEDED(hr)) {
            log("RaspWrapCredential::GetFieldState(): this(%p): dwFieldID=%d *pcpfs=%d\n", this, dwFieldID, *pcpfs);
        }
    }

    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID. We'll check to see if
// it's for us or the wrapped credential, and then handle or route it as appropriate.
HRESULT RaspWrapCredential::GetStringValue(
    __in DWORD dwFieldID,
    __deref_out PWSTR* ppwsz
    )
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredential::GetStringValue(): this(%p): dwFieldID=%d\n", this, dwFieldID);


    if (dwFieldID == _dwWrappedDescriptorCount)
    {
        hr = SHStrDupW(L"Use SSO", ppwsz);
    }
    else if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->GetStringValue(dwFieldID, ppwsz);
        if (SUCCEEDED(hr))
        {
            log("RaspWrapCredential::GetStringValue(): %S\n", *ppwsz ? *ppwsz : L"null");
        }
    }

    return hr;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the
// currently selected item (pdwSelectedItem). We'll check to see if it's for us or the
// wrapped credential, and then handle or route it as appropriate.
HRESULT RaspWrapCredential::GetComboBoxValueCount(
    __in DWORD dwFieldID,
    __out DWORD* pcItems,
    __out_range(<,*pcItems) DWORD* pdwSelectedItem
    )
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredential::GetComboBoxValueCount(): this(%p): dwFieldID=%d\n", this, dwFieldID);


    if (dwFieldID == _dwWrappedDescriptorCount)
    {
        return hr;
    }

    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->GetComboBoxValueCount(dwFieldID, pcItems, pdwSelectedItem);
    }

    return hr;
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
// We'll check to see if it's for us or the wrapped credential, and then handle or route
// it as appropriate.
HRESULT RaspWrapCredential::GetComboBoxValueAt(
    __in DWORD dwFieldID,
    __in DWORD dwItem,
    __deref_out PWSTR* ppwszItem
    )
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredential::GetComboBoxValueAt(): this(%p): dwFieldID=%d\n", this, dwFieldID);


    if (dwFieldID == _dwWrappedDescriptorCount)
    {
        return hr;
    }

    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->GetComboBoxValueAt(dwFieldID, dwItem, ppwszItem);
    }

    return hr;
}

// Called when the user changes the selected item in the combobox. We'll check to see if
// it's for us or the wrapped credential, and then handle or route it as appropriate.
HRESULT RaspWrapCredential::SetComboBoxSelectedValue(
    __in DWORD dwFieldID,
    __in DWORD dwSelectedItem
    )
{
    HRESULT hr = E_UNEXPECTED;
    log("RaspWrapCredential::SetComboBoxSelectedValue(): this(%p): dwFieldID=%d\n", this, dwFieldID);

    if (dwFieldID == _dwWrappedDescriptorCount)
    {
        return hr;
    }

    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->SetComboBoxSelectedValue(dwFieldID, dwSelectedItem);
    }

    return hr;
}

// The following methods are for logonUI to get the values of various UI elements and
// then communicate to the credential about what the user did in that field. Even though
// we don't offer these field types ourselves, we need to pass along the request to the
// wrapped credential.

HRESULT RaspWrapCredential::GetBitmapValue(
    __in DWORD dwFieldID,
    __out HBITMAP* phbmp
    )
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredential::GetBitmapValue(): this(%p): dwFieldID=%d\n", this, dwFieldID);

    if (dwFieldID == _dwWrappedDescriptorCount)
    {
        return hr;
    }

    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->GetBitmapValue(dwFieldID, phbmp);
    }

    return hr;
}

HRESULT RaspWrapCredential::GetSubmitButtonValue(
    __in DWORD dwFieldID,
    __out DWORD* pdwAdjacentTo
    )
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredential::GetSubmitButtonValue(): this(%p): dwFieldID=%d\n", this, dwFieldID);


    if (dwFieldID == _dwWrappedDescriptorCount)
    {
        return hr;
    }

    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->GetSubmitButtonValue(dwFieldID, pdwAdjacentTo);
    }

    return hr;
}

HRESULT RaspWrapCredential::SetStringValue(
    __in DWORD dwFieldID,
    __in PCWSTR pwz
    )
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredential::SetStringValue(): this(%p): dwFieldID=%d\n", this, dwFieldID);
    log("RaspWrapCredential::SetStringValue(): %S\n", pwz ? pwz : L"null");

    if (dwFieldID == _dwWrappedDescriptorCount)
    {
        return hr;
    }

    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->SetStringValue(dwFieldID, pwz);
    }

    return hr;

}

HRESULT RaspWrapCredential::GetCheckboxValue(
    __in DWORD dwFieldID,
    __out BOOL* pbChecked,
    __deref_out PWSTR* ppwszLabel
    )
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredential::GetCheckboxValue(): this(%p): dwFieldID=%d\n", this, dwFieldID);


    if (dwFieldID == _dwWrappedDescriptorCount)
    {
        *pbChecked = _bUseSSOChecked;
        hr = SHStrDupW(L"Use SSO", ppwszLabel); // caller should free
    }
    else if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->GetCheckboxValue(dwFieldID, pbChecked, ppwszLabel);
    }

    return hr;
}

HRESULT RaspWrapCredential::SetCheckboxValue(
    __in DWORD dwFieldID,
    __in BOOL bChecked
    )
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredential::SetCheckboxValue(): this(%p): dwFieldID=%d\n", this, dwFieldID);

    if (dwFieldID == _dwWrappedDescriptorCount)
    {
        _bUseSSOChecked = bChecked;
        return S_OK;
    }

    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->SetCheckboxValue(dwFieldID, bChecked);
    }

    return hr;
}

HRESULT RaspWrapCredential::CommandLinkClicked(__in DWORD dwFieldID)
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredential::CommandLinkClicked(): this(%p): dwFieldID=%d\n", this, dwFieldID);

    if (dwFieldID == _dwWrappedDescriptorCount)
    {
        return hr;
    }

    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->CommandLinkClicked(dwFieldID);
    }

    return hr;
}

//
// Collect the username and password into a serialized credential for the correct usage scenario
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials
// back to the system to log on.
//
HRESULT RaspWrapCredential::GetSerialization(
    __out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    __deref_out_opt PWSTR* ppwszOptionalStatusText,
    __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
    HRESULT hr = E_UNEXPECTED;

    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->GetSerialization(pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
    }

    if (!_bUseSSOChecked)
    {
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
    }

    log("RaspWrapCredential::GetSerialization(): this(%p)\n", this);


    return hr;
}

/* IConnectableCredentialProviderCredential */
HRESULT RaspWrapCredential::Connect(IQueryContinueWithStatus* pqcws)
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredential::Connect(): this(%p)\n", this);

    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->Connect(pqcws);
    }

    log("RaspWrapCredential::Connect(): this(%p) returned\n", this);

    return hr;
}

HRESULT RaspWrapCredential::Disconnect()
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredential::Disconnect(): this(%p)\n", this);

    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->Disconnect();
    }

    log("RaspWrapCredential::Disconnect(): this(%p) returned\n", this);

    return hr;
}

// ReportResult is completely optional. However, we will hand it off to the wrapped
// credential in case they want to handle it.
HRESULT RaspWrapCredential::ReportResult(
    __in NTSTATUS ntsStatus,
    __in NTSTATUS ntsSubstatus,
    __deref_out_opt PWSTR* ppwszOptionalStatusText,
    __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredential::ReportResult(): this(%p)\n", this);


    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->ReportResult(ntsStatus, ntsSubstatus, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
    }

    return hr;
}

void RaspWrapCredential::_CleanupEvents()
{
    // Call Uninitialize before releasing our reference on the real
    // ICredentialProviderCredentialEvents to avoid having an
    // invalid reference.
    if (_pWrappedCredentialEvents != NULL)
    {
        _pWrappedCredentialEvents->Uninitialize();
        _pWrappedCredentialEvents->Release();
        _pWrappedCredentialEvents = NULL;
    }

    if (_pCredProvCredentialEvents != NULL)
    {
        _pCredProvCredentialEvents->Release();
        _pCredProvCredentialEvents = NULL;
    }
}
