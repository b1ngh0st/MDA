#include <windows.h>

DWORD WINAPI ShowMsgBox(LPVOID lpParam)
{
    // Show MessageBox and wait for user
    MessageBoxA(NULL, "Hello from injected DLL!", "Injected!", MB_OK | MB_TOPMOST);
    
    // Keep thread alive (optional, e.g., sleep for 30s)
    Sleep(30000); // keep thread alive for 30 seconds
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        CreateThread(NULL, 0, ShowMsgBox, NULL, 0, NULL);
    }
    return TRUE;
}
