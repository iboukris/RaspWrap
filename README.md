---
page_type: sample
languages:
- cpp
name: RaspWrap
description: Extends Microsoft's wrap-existing-credential-provider sample to wrap the RAS Provider
---

# RaspWrap Pre-Logon Provider

The Windows RAS allows establishing dial-up and/or VPN connections in pre-logon
via the RAS pre-logon provider (PLAP).  It has, however, this annoying limitation,
where it assumes the same crednetials used for the network connection should also
be used to logon to Windows. So when the credentials differ, if the network credentials
are entered, the connection will be established, but the logon will fail and the user
does not have the option to enter other credentials to logon with.  If, on the other
hand, the Windows credentials are entered then either the network connection will fail,
or, if the provider doesn't care about the entered credentials (e.g. it has other means
to track the usage, as is often the case on 4G mobile networks), then everything will
work, except you'd be handing off your Windows/AD credentials to the ISP (which I
suspect happens quite often).

The RaspWrap attempts to fix this, by extending Microsoft's credential-provider
samplewrapexistingcredentialprovider sample (see link below), in order to wrap
the RAS Provider (CLSID_RASProvider) and add a "Use SSO" checkbox to allow
using different credentials for network and local logon.

It does that by implementing the IConnectableCredentialProviderCredential
interface, that is, adding the Connect/Disconnect methods, and by implementing
the ICredentialProviderFilter interface, in order to filter out the real RASProvider,
thus avoiding two connect-buttons from being shown.


## Links:

- Microsoft's original credential-provider samplewrapexistingcredentialprovider sample:

https://github.com/microsoft/Windows-classic-samples/tree/master/Samples/Win7Samples/security/credentialproviders/samplewrapexistingcredentialprovider

- How to build debug and test (downlowd the mht file and open in IE):

https://github.com/microsoft/Windows-classic-samples/blob/master/Samples/Win7Samples/security/credentialproviders/Credential%20Provider%20Samples%20Overview.mht

- Many useful links and contents, at:

https://github.com/DavidWeiss2/windows-Credential-Provider-library

## Operating system requirements

Tested on Windows 10.

## Build the sample

1. Start Visual Studio and select **File** \> **Open** \> **Project/Solution**.
2. Go to the directory named for the sample, and double-click the Visual Studio Solution (.sln) file.
3. Press F7 or use **Build** \> **Build Solution** to build the sample.
