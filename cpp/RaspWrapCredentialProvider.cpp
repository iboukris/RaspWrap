//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// This implements ICredentialProvider, which is the main
// interface that logonUI uses to decide which tiles to display.
// In this sample, we are wrapping the default password provider with
// an extra small text and combobox. We pass nearly all requests to the
// wrapped provider, except for the ones that are for fields we're
// responsible for ourselves. As far as the owner is concerned, we are a
// unique provider, so they never know we're wrapping another provider.

#include <new>
#include <credentialprovider.h>
#include "RaspWrapCredentialProvider.h"
#include "RaspWrapCredential.h"
#include "guid.h"


RaspWrapCredentialProvider::RaspWrapCredentialProvider():
    _cRef(1)
{
    DllAddRef();

    log("RaspWrapCredentialProvider::RaspWrapCredentialProvider(): this(%p)\n", this);

    _pWrappedProvider = NULL;
    _dwWrappedDescriptorCount = 0;
}

RaspWrapCredentialProvider::~RaspWrapCredentialProvider()
{
    log("RaspWrapCredentialProvider::~RaspWrapCredentialProvider(): this(%p)\n", this);

    if (_pWrappedProvider)
    {
        _pWrappedProvider->Release();
    }

    DllRelease();
}

// Ordinarily we would look at the CPUS and decide whether or not we support this scenario.
// However, in this scenario we're going to create our internal provider and let it answer
// questions like this for us.
HRESULT RaspWrapCredentialProvider::SetUsageScenario(
    __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    __in DWORD dwFlags
    )
{
    HRESULT hr = S_OK;

    log("RaspWrapCredentialProvider::SetUsageScenario: this(%p): cpus=%d\n", this, cpus);

    // We expect the RAS Provider to only implements the PLAP scenario.
    if (cpus != CPUS_PLAP)
    {
        return E_NOTIMPL;
    }

    // Create the RASP PLAP credential provider if we don't already have one,
    // and query its interface for an ICredentialProvider we can use.
    if (_pWrappedProvider == NULL)
    {
        hr = CoCreateInstance(CLSID_RASProvider, NULL, CLSCTX_ALL,
                              IID_PPV_ARGS(&_pWrappedProvider));
    }

    if (SUCCEEDED(hr))
    {
        DWORD count;

        // Once the provider is up and running, ask it about the usage scenario
        // being provided.
        hr = _pWrappedProvider->SetUsageScenario(cpus, dwFlags);
        if (FAILED(hr)) {
            return hr;
        }

        /* Now that we have the wrapped provider, let's check its descriptor count */
        hr = GetFieldDescriptorCount(&count);
    }

    return hr;
}

// We pass this along to the wrapped provider.
HRESULT RaspWrapCredentialProvider::SetSerialization(
    __in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs
    )
{
    HRESULT hr = E_UNEXPECTED;
    log("RaspWrapCredentialProvider::SetSerialization: this(%p)\n", this);

    if (_pWrappedProvider != NULL)
    {
        hr = _pWrappedProvider->SetSerialization(pcpcs);
    }

    return hr;
}

// Called by LogonUI to give you a callback. We pass this along to the wrapped provider.
HRESULT RaspWrapCredentialProvider::Advise(
    __in ICredentialProviderEvents* pcpe,
    __in UINT_PTR upAdviseContext
    )
{
    HRESULT hr = E_UNEXPECTED;
    log("RaspWrapCredentialProvider::Advise: this(%p)\n", this);

    if (_pWrappedProvider != NULL)
    {
        hr = _pWrappedProvider->Advise(pcpe, upAdviseContext);
    }
    return hr;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
// We pass this along to the wrapped provider.
HRESULT RaspWrapCredentialProvider::UnAdvise()
{
    HRESULT hr = E_UNEXPECTED;
    log("RaspWrapCredentialProvider::UnAdvise: this(%p)\n", this);

    if (_pWrappedProvider != NULL)
    {
        hr = _pWrappedProvider->UnAdvise();
    }
    return hr;
}

// Called by LogonUI to determine the number of fields in your tiles.  This
// does mean that all your tiles must have the same number of fields.
// This number must include both visible and invisible fields. If you want a tile
// to have different fields from the other tiles you enumerate for a given usage
// scenario you must include them all in this count and then hide/show them as desired
// using the field descriptors. We pass this along to the wrapped provider and then append
// our own credential count.
HRESULT RaspWrapCredentialProvider::GetFieldDescriptorCount(
    __out DWORD* pdwCount
    )
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredentialProvider::GetFieldDescriptorCount: this(%p)\n", this);

    if (_pWrappedProvider != NULL)
    {
        hr = _pWrappedProvider->GetFieldDescriptorCount(&(_dwWrappedDescriptorCount));
        if (SUCCEEDED(hr))
        {
            // Account for our UseSSO checkbox
            *pdwCount = _dwWrappedDescriptorCount + 1;
        }
    }

    return hr;
}

// Gets the field descriptor for a particular field. If this descriptor refers to one owned
// by our wrapped provider, we'll pass it along. Otherwise we provide our own.
HRESULT RaspWrapCredentialProvider::GetFieldDescriptorAt(
    __in DWORD dwIndex,
    __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
    )
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredentialProvider::GetFieldDescriptorAt: this(%p)\n", this);

    if (_pWrappedProvider == NULL || ppcpfd == NULL)
    {
        return hr;
    }

    if (dwIndex == _dwWrappedDescriptorCount)
    {
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR cpfd = { dwIndex, CPFT_CHECKBOX, L"USe SSO", {0} };
        hr = FieldDescriptorCoAllocCopy(cpfd, ppcpfd);
    }
    else
    {
        hr = _pWrappedProvider->GetFieldDescriptorAt(dwIndex, ppcpfd);
        if (SUCCEEDED(hr))
        {
            log("RaspWrapCredentialProvider::GetFieldDescriptorAt: dwFieldID=%d cpft=%d\n",
                (*ppcpfd)->dwFieldID, (*ppcpfd)->cpft);
        }
    }

    return hr;
}

// Sets pdwCount to the number of tiles that we wish to show at this time.
// Sets pdwDefault to the index of the tile which should be used as the default.
// The default tile is the tile which will be shown in the zoomed view by default. If
// more than one provider specifies a default tile the last cred prov used can select
// the default tile.
// If *pbAutoLogonWithDefault is TRUE, LogonUI will immediately call GetSerialization
// on the credential you've specified as the default and will submit that credential
// for authentication without showing any further UI.
HRESULT RaspWrapCredentialProvider::GetCredentialCount(
    __out DWORD* pdwCount,
    __out_range(<,*pdwCount) DWORD* pdwDefault,
    __out BOOL* pbAutoLogonWithDefault
    )
{
    HRESULT hr = E_UNEXPECTED;

    log("RaspWrapCredentialProvider::GetCredentialCount: this(%p)\n", this);

    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = false;

    if (_pWrappedProvider != NULL)
    {
        hr = _pWrappedProvider->GetCredentialCount(pdwCount, pdwDefault, pbAutoLogonWithDefault);
        if (SUCCEEDED(hr)) {
            log("RaspWrapCredentialProvider::GetCredentialCount: this(%p): pbAutoLogonWithDefault=%d\n",
                this, *pbAutoLogonWithDefault);
        }
        else
        {
            log("RaspWrapCredentialProvider::GetCredentialCount: this(%p): upcall failed\n");
        }
    }

    return hr;
}

// Returns the credential at the index specified by dwIndex. This function is called by
// logonUI to enumerate the tiles.
HRESULT RaspWrapCredentialProvider::GetCredentialAt(
    __in DWORD dwIndex,
    __deref_out ICredentialProviderCredential** ppcpc
    )
{
    HRESULT hr = E_UNEXPECTED;
    ICredentialProviderCredential* pCredential;
    IConnectableCredentialProviderCredential* pConCred;
    RaspWrapCredential* wrapper;

    log("RaspWrapCredentialProvider::GetCredentialAt: dwIndex=%d this(%p)\n", dwIndex, this);

    if (_pWrappedProvider == NULL)
    {
        return hr;
    }

    hr = _pWrappedProvider->GetCredentialAt(dwIndex, &pCredential);
    if (FAILED(hr))
    {
        return hr;
    }

    log("RaspWrapCredentialProvider::GetCredentialAt: pCredential(%p)\n", pCredential);

    /* We're only interested in wrapping connectable credentials */
    hr = pCredential->QueryInterface(IID_PPV_ARGS(&(pConCred)));
    pCredential->Release();
    if (FAILED(hr))
    {
        /* Shouldn't happen with the RAS backend */
        log("RaspWrapCredentialProvider::GetCredentialAt: pCredential(%p) not connectable\n", pCredential);
        return hr;
    }

    wrapper = new (std::nothrow) RaspWrapCredential();
    if (wrapper == NULL) {
        pConCred->Release();
        return E_OUTOFMEMORY;
    }

    log("RaspWrapCredentialProvider::GetCredentialAt: wrapper(%p) wraps pConCred(%p)\n", wrapper, pConCred);

    hr = wrapper->Initialize(pConCred, _dwWrappedDescriptorCount);
    pConCred->Release();
    if (SUCCEEDED(hr)) {
        *ppcpc = wrapper;
    }
    else
    {
        delete wrapper;
    }

    return hr;
}

HRESULT RaspWrapCredentialProvider::Filter(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags,
    GUID* rgclsidProviders,
    BOOL* rgbAllow,
    DWORD cProviders)
{
    UNREFERENCED_PARAMETER(dwFlags);

    log("RaspWrapCredentialProvider::Filter: this(%p): cpus=%d\n", this, cpus);

    if (cpus != CPUS_PLAP) {
        return S_OK;
    }

    for (size_t i = 0; i < cProviders; i++)
    {
        if (IsEqualGUID(rgclsidProviders[i], CLSID_RASProvider))
        {
            rgbAllow[i] = false;
            log("RaspWrapCredentialProvider::Filter: this(%p): filtered out CLSID_RASProvider\n", this);

        }
    }

    return S_OK;
}

HRESULT RaspWrapCredentialProvider::UpdateRemoteCredential(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsIn,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsOut)
{
    UNREFERENCED_PARAMETER(pcpcsOut);
    UNREFERENCED_PARAMETER(pcpcsIn);
    log("RaspWrapCredentialProvider::UpdateRemoteCredential: this(%p)\n", this);
    return E_NOTIMPL;
}

// Boilerplate code to create our provider.
HRESULT RaspWrap_CreateInstance(__in REFIID riid, __deref_out void** ppv)
{
    HRESULT hr;

    RaspWrapCredentialProvider* pProvider = new (std::nothrow) RaspWrapCredentialProvider();

    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}
