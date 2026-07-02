#pragma once

#include <Windows.h>
#include <winhttp.h>

namespace NetDownloader {
	enum STATUS {
		ND_STATUS_SUCCESS,
		ND_STATUS_INVALID_PARAMETER,
	};

	STATUS Create(const wchar_t* Proxy);
}