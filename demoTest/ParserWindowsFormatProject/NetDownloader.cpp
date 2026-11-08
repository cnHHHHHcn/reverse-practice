#pragma once

#include "NetDownloader.h"
#include <stdio.h>

NetDownloader::STATUS NetDownloader::Create(const wchar_t* UserAgent){
    DWORD data;
    DWORD dwSize = sizeof(DWORD);

    // Use WinHttpOpen to obtain an HINTERNET handle.
    HINTERNET hSession = WinHttpOpen(UserAgent,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession)
    {


        // Use WinHttpQueryOption to retrieve internet options.
        if (WinHttpQueryOption(hSession,
            WINHTTP_OPTION_CONNECT_TIMEOUT,
            &data, &dwSize))
        {
            printf("Connection timeout: %u ms\n\n", data);
        }
        else
        {
            printf("Error %u in WinHttpQueryOption.\n",
                GetLastError());
        }

        // When finished, release the HINTERNET handle.
        WinHttpCloseHandle(hSession);
    }
    else
    {
        printf("Error %u in WinHttpOpen.\n", GetLastError());
    }
	return ND_STATUS_SUCCESS;
}
