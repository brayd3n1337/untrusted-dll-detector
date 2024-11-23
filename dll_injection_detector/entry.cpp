#include <iostream>
#include <windows.h>
#include <Tlhelp32.h>
#include <Psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <future>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "Crypt32.lib")

DWORD find_pid( const std::wstring& name ) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof( PROCESSENTRY32 );

    HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL );
    if ( snapshot == INVALID_HANDLE_VALUE ) {
        std::wcerr << L"Failed to create snapshot of processes." << std::endl;
        return 0;
    }

    if ( Process32First( snapshot, &entry ) == TRUE ) {
        do {
            if ( _wcsicmp( entry.szExeFile, name.c_str( ) ) == 0 ) {
                CloseHandle( snapshot );
                return entry.th32ProcessID;
            }
        } while ( Process32Next( snapshot, &entry ) == TRUE );
    }

    CloseHandle( snapshot );
    std::wcerr << L"Process not found: " << name << std::endl;
    return 0;
}

bool is_signed_by_microsoft( const std::wstring& filePath ) 
{
    WINTRUST_FILE_INFO fileData = { 0 };
    fileData.cbStruct = sizeof( WINTRUST_FILE_INFO );
    fileData.pcwszFilePath = filePath.c_str( );
    fileData.hFile = nullptr;
    fileData.pgKnownSubject = nullptr;

    WINTRUST_DATA winTrustData = { 0 };
    winTrustData.cbStruct = sizeof( WINTRUST_DATA );
    winTrustData.pPolicyCallbackData = nullptr;
    winTrustData.pSIPClientData = nullptr;
    winTrustData.dwUIChoice = WTD_UI_NONE;  
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileData;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.hWVTStateData = nullptr;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;  // only accept trusted publishers

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG status = WinVerifyTrust( nullptr, &policyGUID, &winTrustData );
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    if ( status == ERROR_SUCCESS )
    {
        HCERTSTORE hStore;
        HCRYPTMSG hMsg;
        PCCERT_CONTEXT pCertContext = nullptr;
        if ( CryptQueryObject( CERT_QUERY_OBJECT_FILE, filePath.c_str( ),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY, 0,
            nullptr, nullptr, nullptr, &hStore, &hMsg, nullptr ) ) 
        {

            while ( ( pCertContext = CertEnumCertificatesInStore( hStore, pCertContext ) ) != nullptr )
            {
                // calculate required buffer size dynamically
                DWORD dwSize = CertGetNameStringW( pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0 );

                if ( dwSize > 0 )
                {
					// create a dynamically allocated buffer to store the certificate name
                    wchar_t* buffer = new wchar_t[dwSize];

                    if ( CertGetNameStringW( pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buffer, dwSize ) > 0 )
                    {
                        std::wstring certName( buffer );


                        if ( certName.find( L"Microsoft" ) != std::wstring::npos ) 
                        {
                            CertFreeCertificateContext( pCertContext );
                            CertCloseStore( hStore, 0 );
                            delete[] buffer;

                            // prevention of dangling pointer doesnt really matter but good practice
                            buffer = nullptr;
                            return true;
                        }
                    }

                    delete[] buffer; 
                    buffer = nullptr;
                }
            }

            CertCloseStore( hStore, 0 );
        }
    }
    return false;
}

std::vector<std::wstring> find_microsoft_signed_dlls( ) 
{
    std::vector<std::wstring> microsoftDlls;
    wchar_t system32Path[MAX_PATH];

    // entire into the system32 directory
    if ( !GetSystemDirectoryW( system32Path, MAX_PATH ) ) 
    {
        std::wcerr << L"Failed to get System32 path." << std::endl;
        return microsoftDlls;
    }

    // search for all dll's
    std::wstring searchPath = std::wstring( system32Path ) + L"\\*.dll";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW( searchPath.c_str( ), &findData );

    // if there is no dll entries in the directory return
    if ( hFind == INVALID_HANDLE_VALUE )
    {
        std::wcerr << L"Failed to enumerate DLLs in System32." << std::endl;
        return microsoftDlls;
    }

	// find all the dll's that are signed by Microsoft
    do 
    {
        std::wstring fullPath = std::wstring( system32Path ) + L"\\" + findData.cFileName;
        if ( !is_signed_by_microsoft( fullPath ) ) 
        {
            microsoftDlls.push_back( fullPath );
        }
    } while ( FindNextFileW( hFind, &findData ) != 0 );

    FindClose( hFind );
    return microsoftDlls;
}

void check_dll_signing( const std::wstring& filePath, std::vector<std::wstring>& results, std::mutex& mtx ) 
{
	// if the DLL is not signed by Microsoft, add it to the results
    if ( !is_signed_by_microsoft( filePath ) )
    {
        std::lock_guard<std::mutex> lock( mtx );
        results.push_back( filePath );
    }
}

int main( ) {
    const DWORD pid = find_pid( L"notepad.exe" );

    if ( pid == 0 ) 
    {
        std::cout << "Process not found\n";
        return 1;
    }

    const HANDLE process = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid );

    if ( process == nullptr )
    {
        std::wcerr << L"Failed to open process with PID: " << pid << std::endl;
        return 1;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;

	// enumerate all modules in the process
    if ( EnumProcessModules( process, hMods, sizeof( hMods ), &cbNeeded ) ) 
    {
        std::vector<std::wstring> results;
        std::mutex mtx;
        std::vector<std::future<void>> tasks;

		// check if the DLL is signed by Microsoft
        for ( unsigned int i = 0; i < ( cbNeeded / sizeof( HMODULE ) ); i++ ) 
        {
            TCHAR szModName[MAX_PATH];
            if ( GetModuleFileNameEx( process, hMods[i], szModName, sizeof( szModName ) / sizeof( TCHAR ) ) ) 
            {
                std::wstring dllPath( szModName );
                tasks.push_back( std::async( std::launch::async, check_dll_signing, dllPath, std::ref( results ), std::ref( mtx ) ) );
            }
        }

		// wait for all tasks to finish
        for ( auto& task : tasks ) 
        {
            task.get( );
        }

		// print unsigned DLLs
        std::wcout << L"Unsigned DLLs found:\n";

        // could add you're own logic here to handle trusted unsigned dll entries
        for ( const auto& dll : results ) {
            std::wcout << dll << std::endl;
        }
    }

    CloseHandle( process );

    return 0;
}
