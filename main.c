#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

void PrintBanner() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    FILE* banner = _wfopen(L"banner.txt", L"rb");
    if (!banner)
        return;

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), banner)) {
        printf("%s", buffer);
    }
    fclose(banner);
}

void PrintHelp(LPWSTR progName) {
    wprintf(L"\nusage: %s [options] <argument>\n\n", progName);
    wprintf(L"options:\n");
    wprintf(L"  -i, --inspect <process_name>    inspect process and display information\n");
    wprintf(L"  -h, --help                      display this help message\n\n");
    wprintf(L"examples:\n");
    wprintf(L"  %s -i notepad.exe\n", progName);
    wprintf(L"  %s --inspect chrome.exe\n", progName);
}

int LevenshteinDistance(LPCWSTR s1, LPCWSTR s2) {
    int len1 = lstrlenW(s1);
    int len2 = lstrlenW(s2);
    int* prev = (int*)malloc((len2 + 1) * sizeof(int));
    int* curr = (int*)malloc((len2 + 1) * sizeof(int));

    for (int j = 0; j <= len2; j++) prev[j] = j;

    for (int i = 1; i <= len1; i++) {
        curr[0] = i;
        for (int j = 1; j <= len2; j++) {
            int cost = (towlower(s1[i - 1]) == towlower(s2[j - 1])) ? 0 : 1;
            curr[j] = min(min(curr[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
        }
        int* temp = prev;
        prev = curr;
        curr = temp;
    }

    int result = prev[len2];
    free(prev);
    free(curr);
    return result;
}

BOOL ContainsSubstring(LPCWSTR haystack, LPCWSTR needle) {
    WCHAR lowerHaystack[MAX_PATH * 2] = { 0 };
    WCHAR lowerNeedle[MAX_PATH * 2] = { 0 };

    for (DWORD i = 0; i < lstrlenW(haystack) && i < MAX_PATH * 2 - 1; i++)
        lowerHaystack[i] = towlower(haystack[i]);
    for (DWORD i = 0; i < lstrlenW(needle) && i < MAX_PATH * 2 - 1; i++)
        lowerNeedle[i] = towlower(needle[i]);

    return wcsstr(lowerHaystack, lowerNeedle) != NULL;
}

typedef struct {
    WCHAR name[MAX_PATH];
    int distance;
} ProcessSuggestion;

int CompareSuggestions(const void* a, const void* b) {
    return ((ProcessSuggestion*)a)->distance - ((ProcessSuggestion*)b)->distance;
}

void FindSimilarProcesses(LPWSTR searchName, ProcessSuggestion* suggestions, int* count, int maxSuggestions) {
    PROCESSENTRY32 pe32 = { .dwSize = sizeof(PROCESSENTRY32) };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    *count = 0;
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    if (Process32First(hSnapshot, &pe32)) {
        do {
            BOOL exists = FALSE;
            for (int i = 0; i < *count; i++) {
                if (wcscmp(suggestions[i].name, pe32.szExeFile) == 0) { exists = TRUE; break; }
            }
            if (!exists) {
                int distance = LevenshteinDistance(searchName, pe32.szExeFile);
                BOOL contains = ContainsSubstring(pe32.szExeFile, searchName);
                if (contains || distance <= 5) {
                    if (contains) distance -= 3;
                    wcscpy_s(suggestions[*count].name, MAX_PATH, pe32.szExeFile);
                    suggestions[*count].distance = distance;
                    (*count)++;
                    if (*count >= maxSuggestions) break;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    qsort(suggestions, *count, sizeof(ProcessSuggestion), CompareSuggestions);
}

BOOL ProcEnum(LPWSTR szProcessName, DWORD* dwProcId, HANDLE* hProcess) {
    PROCESSENTRY32 Proc = { .dwSize = sizeof(PROCESSENTRY32) };
    HANDLE hSnapshot = NULL;

    *dwProcId = 0;
    *hProcess = NULL;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        wprintf(L"create snapshot failed %d\n", GetLastError());
        goto _EndOfFunction;
    }

    if (!Process32First(hSnapshot, &Proc)) {
        wprintf(L"process32first failed %d\n", GetLastError());
        goto _EndOfFunction;
    }

    WCHAR LowerSearchName[MAX_PATH * 2] = { 0 };
    DWORD searchLen = lstrlenW(szProcessName);
    if (searchLen < MAX_PATH * 2) {
        for (DWORD i = 0; i < searchLen; i++)
            LowerSearchName[i] = (WCHAR)towlower(szProcessName[i]);
        LowerSearchName[searchLen] = L'\0';
    }

    do {
        WCHAR LowerName[MAX_PATH * 2] = { 0 };
        DWORD dwSize = lstrlenW(Proc.szExeFile);
        if (dwSize < MAX_PATH * 2) {
            for (DWORD i = 0; i < dwSize; i++)
                LowerName[i] = (WCHAR)towlower(Proc.szExeFile[i]);
            LowerName[dwSize] = L'\0';
        }

        if (wcscmp(LowerName, LowerSearchName) == 0) {
            *dwProcId = Proc.th32ProcessID;
            *hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Proc.th32ProcessID);
            break;
        }
    } while (Process32Next(hSnapshot, &Proc));

_EndOfFunction:
    if (hSnapshot != NULL && hSnapshot != INVALID_HANDLE_VALUE)
        CloseHandle(hSnapshot);

    return *dwProcId != 0;
}

void InspectProc(LPWSTR processName) {
    DWORD dwProcId = 0;
    HANDLE hProcess = NULL;

    if (!ProcEnum(processName, &dwProcId, &hProcess)) {
        wprintf(L"\nprocess '%s' not found\n\n", processName);

        ProcessSuggestion suggestions[10];
        int suggestionCount = 0;
        FindSimilarProcesses(processName, suggestions, &suggestionCount, 10);

        if (suggestionCount > 0) {
            wprintf(L"did you mean:\n");
            for (int i = 0; i < suggestionCount && i < 5; i++)
                wprintf(L"  - %s\n", suggestions[i].name);
        }
        return;
    }

    wprintf(L"\n%ls\n", processName);
    wprintf(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    wprintf(L"basic\n");
    wprintf(L"  pid                    %lu\n", dwProcId);

    if (hProcess) {
        HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32 = { .dwSize = sizeof(PROCESSENTRY32) };
            WCHAR parentName[MAX_PATH] = L"unknown";
            DWORD parentPid = 0;

            if (Process32First(hProcSnap, &pe32)) {
                do {
                    if (pe32.th32ProcessID == dwProcId) {
                        parentPid = pe32.th32ParentProcessID;
                        wprintf(L"  base priority          %ld\n", pe32.pcPriClassBase);
                        break;
                    }
                } while (Process32Next(hProcSnap, &pe32));
            }

            if (parentPid > 0 && Process32First(hProcSnap, &pe32)) {
                do {
                    if (pe32.th32ProcessID == parentPid) {
                        wcscpy_s(parentName, MAX_PATH, pe32.szExeFile);
                        break;
                    }
                } while (Process32Next(hProcSnap, &pe32));
            }

            wprintf(L"  parent pid             %lu (%ls)\n", parentPid, parentName);
            CloseHandle(hProcSnap);
        }

        HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        DWORD threadCount = 0;
        if (hThreadSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te = { .dwSize = sizeof(THREADENTRY32) };
            if (Thread32First(hThreadSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID == dwProcId)
                        threadCount++;
                } while (Thread32Next(hThreadSnap, &te));
            }
            CloseHandle(hThreadSnap);
        }
        wprintf(L"  threads                %lu\n", threadCount);

        BOOL isElevated = FALSE;
        HANDLE hToken = NULL;
        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD size;
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
                isElevated = elevation.TokenIsElevated;
            }
            CloseHandle(hToken);
        }
        wprintf(L"  elevated               %ls\n", isElevated ? L"yes" : L"no");

        wprintf(L"\nmemory\n");
        PROCESS_MEMORY_COUNTERS_EX pmcEx = { 0 };
        pmcEx.cb = sizeof(pmcEx);
        if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmcEx, sizeof(pmcEx))) {
            wprintf(L"  working set            %llu kb\n", (unsigned long long)(pmcEx.WorkingSetSize / 1024));
            wprintf(L"  peak working set       %llu kb\n", (unsigned long long)(pmcEx.PeakWorkingSetSize / 1024));
            wprintf(L"  private bytes          %llu kb\n", (unsigned long long)(pmcEx.PrivateUsage / 1024));
            wprintf(L"  pagefile usage         %llu kb\n", (unsigned long long)(pmcEx.PagefileUsage / 1024));
            wprintf(L"  peak pagefile          %llu kb\n", (unsigned long long)(pmcEx.PeakPagefileUsage / 1024));
            wprintf(L"  page faults            %lu\n", pmcEx.PageFaultCount);
        }

        wprintf(L"\ni/o counters\n");
        IO_COUNTERS ioCounters = { 0 };
        if (GetProcessIoCounters(hProcess, &ioCounters)) {
            wprintf(L"  read operations        %llu\n", ioCounters.ReadOperationCount);
            wprintf(L"  write operations       %llu\n", ioCounters.WriteOperationCount);
            wprintf(L"  other operations       %llu\n", ioCounters.OtherOperationCount);
            wprintf(L"  read bytes             %llu kb\n", ioCounters.ReadTransferCount / 1024);
            wprintf(L"  write bytes            %llu kb\n", ioCounters.WriteTransferCount / 1024);
            wprintf(L"  other bytes            %llu kb\n", ioCounters.OtherTransferCount / 1024);
        }

        wprintf(L"\nhandles\n");
        DWORD handleCount = 0;
        if (GetProcessHandleCount(hProcess, &handleCount)) {
            wprintf(L"  handle count           %lu\n", handleCount);
        }

        DWORD gdiObjects = GetGuiResources(hProcess, GR_GDIOBJECTS);
        DWORD userObjects = GetGuiResources(hProcess, GR_USEROBJECTS);
        if (gdiObjects || userObjects) {
            wprintf(L"  gdi objects            %lu\n", gdiObjects);
            wprintf(L"  user objects           %lu\n", userObjects);
        }

        wprintf(L"\npriority\n");
        DWORD priorityClass = GetPriorityClass(hProcess);
        wprintf(L"  priority class         ");
        switch (priorityClass) {
        case IDLE_PRIORITY_CLASS: wprintf(L"idle\n"); break;
        case BELOW_NORMAL_PRIORITY_CLASS: wprintf(L"below normal\n"); break;
        case NORMAL_PRIORITY_CLASS: wprintf(L"normal\n"); break;
        case ABOVE_NORMAL_PRIORITY_CLASS: wprintf(L"above normal\n"); break;
        case HIGH_PRIORITY_CLASS: wprintf(L"high\n"); break;
        case REALTIME_PRIORITY_CLASS: wprintf(L"realtime\n"); break;
        default: wprintf(L"unknown\n"); break;
        }

        DWORD depFlags = 0;
        BOOL depPermanent = FALSE;
        if (GetProcessDEPPolicy(hProcess, &depFlags, &depPermanent)) {
            wprintf(L"  dep enabled            %ls%ls\n",
                (depFlags & PROCESS_DEP_ENABLE) ? L"yes" : L"no",
                depPermanent ? L" (permanent)" : L"");
        }

        wprintf(L"\npath\n");
        WCHAR exePath[MAX_PATH * 2] = { 0 };
        DWORD pathLen = MAX_PATH * 2;
        if (QueryFullProcessImageNameW(hProcess, 0, exePath, &pathLen)) {
            wprintf(L"  executable             %ls\n", exePath);

            WIN32_FILE_ATTRIBUTE_DATA fileData;
            if (GetFileAttributesExW(exePath, GetFileExInfoStandard, &fileData)) {
                ULARGE_INTEGER fileSize;
                fileSize.LowPart = fileData.nFileSizeLow;
                fileSize.HighPart = fileData.nFileSizeHigh;
                wprintf(L"  file size              %llu kb\n", fileSize.QuadPart / 1024);
            }
        }
        CloseHandle(hProcess);
    }

    wprintf(L"\n");
}

int wmain(int argc, LPWSTR argv[]) {
    PrintBanner();

    if (argc < 2) { PrintHelp(argv[0]); return -1; }

    if (wcscmp(argv[1], L"-h") == 0 || wcscmp(argv[1], L"--help") == 0)
        PrintHelp(argv[0]);
    else if (wcscmp(argv[1], L"-i") == 0 || wcscmp(argv[1], L"--inspect") == 0) {
        if (argc < 3) { wprintf(L"\ninspect flag requires a process name\n"); return -1; }
        InspectProc(argv[2]);
    }
    else {
        wprintf(L"\nunknown option: %ls\n", argv[1]);
        wprintf(L"try '%s --help' for more information\n\n", argv[0]);
        return -1;
    }

    return 0;
}
