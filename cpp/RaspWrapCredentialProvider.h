//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

#pragma once

#include <credentialprovider.h>
#include <windows.h>
#include <strsafe.h>

#include "RaspWrapCredential.h"
#include "helpers.h"

class RaspWrapCredentialProvider : public ICredentialProvider, public ICredentialProviderFilter
{
  public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return ++_cRef;
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        LONG cRef = --_cRef;
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void** ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(RaspWrapCredentialProvider, ICredentialProvider), // IID_ICredentialProvider
            QITABENT(RaspWrapCredentialProvider, ICredentialProviderFilter), // IID_ICredentialProviderFilter

            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }
  public:
    IFACEMETHODIMP SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, __in DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(__in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);

    IFACEMETHODIMP Advise(__in ICredentialProviderEvents* pcpe, __in UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP GetFieldDescriptorCount(__out DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(__in DWORD dwIndex,  __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);

    IFACEMETHODIMP GetCredentialCount(__out DWORD* pdwCount,
                                      __out_range(<,*pdwCount) DWORD* pdwDefault,
                                      __out BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(__in DWORD dwIndex,
                                   __deref_out ICredentialProviderCredential** ppcpc);

    friend HRESULT RaspWrap_CreateInstance(__in REFIID riid, __deref_out void** ppv);

  protected:
    RaspWrapCredentialProvider();
    __override ~RaspWrapCredentialProvider();

public:
    IFACEMETHODIMP Filter(
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        DWORD dwFlags,
        GUID* rgclsidProviders,
        BOOL* rgbAllow,
        DWORD cProviders);
    IFACEMETHODIMP UpdateRemoteCredential(
        const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsIn,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsOut);

private:
    LONG                _cRef;
    ICredentialProvider *_pWrappedProvider;         // Our wrapped provider.
    DWORD               _dwWrappedDescriptorCount;  // The number of fields on each tile of our wrapped provider's
                                                    // credentials.
};
