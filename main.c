#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

void PrintBanner() {
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwMode = 0;
	GetConsoleMode(hOut, &dwMode);
	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	SetConsoleMode(hOut, dwMode);

	SetConsoleOutputCP(CP_UTF8);
	SetConsoleCP(CP_UTF8);

	FILE* banner = _wfopen(L"banner.txt", L"rb");
	if (banner == NULL) {
		return;
	}

	char buffer[1024];
	while (fgets(buffer, sizeof(buffer), banner)) {
		printf("%s", buffer);
	}

	fclose(banner);
}

int LevenshteinDistance(const WCHAR* s1, const WCHAR* s2) {
    int len1 = wcslen(s1);
    int len2 = wcslen(s2);
    int* prev = (int*)malloc((len2 + 1) * sizeof(int));
    int* curr = (int*)malloc((len2 + 1) * sizeof(int));

    for (int i = 0; i <= len2; i++)
        prev[i] = i;

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

BOOL ContainsSubstring(const WCHAR* haystack, const WCHAR* needle) {
    WCHAR lowerHaystack[MAX_PATH * 2] = { 0 };
    WCHAR lowerNeedle[MAX_PATH * 2] = { 0 };

    for (int i = 0; i < wcslen(haystack) && i < MAX_PATH * 2 - 1; i++)
        lowerHaystack[i] = towlower(haystack[i]);

    for (int i = 0; i < wcslen(needle) && i < MAX_PATH * 2 - 1; i++)
        lowerNeedle[i] = towlower(needle[i]);

    return wcsstr(lowerHaystack, lowerNeedle) != NULL;
}

typedef struct {
    WCHAR name[MAX_PATH];
    int distance;
} ProcessSuggestion;

int CompareSuggestions(const void* a, const void* b) {
    ProcessSuggestion* sa = (ProcessSuggestion*)a;
    ProcessSuggestion* sb = (ProcessSuggestion*)b;
    return sa->distance - sb->distance;
}

void FindSimilarProcesses(LPWSTR searchName, ProcessSuggestion* suggestions, int* count, int maxSuggestions) {
    PROCESSENTRY32 pe32 = { .dwSize = sizeof(PROCESSENTRY32) };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    *count = 0;

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    if (Process32First(hSnapshot, &pe32)) {
        do {
            BOOL alreadyAdded = FALSE;
            for (int i = 0; i < *count; i++) {
                if (wcscmp(suggestions[i].name, pe32.szExeFile) == 0) {
                    alreadyAdded = TRUE;
                    break;
                }
            }

            if (!alreadyAdded) {
                int distance = LevenshteinDistance(searchName, pe32.szExeFile);
                BOOL contains = ContainsSubstring(pe32.szExeFile, searchName);

                if (contains || distance <= 5) {
                    if (contains) distance -= 3;

                    wcscpy_s(suggestions[*count].name, MAX_PATH, pe32.szExeFile);
                    suggestions[*count].distance = distance;
                    (*count)++;

                    if (*count >= maxSuggestions)
                        break;
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
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		wprintf(L"[!] CreateToolhelp32Snapshot failed: %d\n", GetLastError());
		goto _EndOfFunction;
	}

	if (!Process32First(hSnapshot, &Proc)) {
		wprintf(L"[!] Process32First failed: %d\n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		WCHAR LowerName[MAX_PATH * 2] = { 0 };
		WCHAR LowerSearchName[MAX_PATH * 2] = { 0 };

		if (Proc.szExeFile) {
			DWORD dwSize = lstrlenW(Proc.szExeFile);
			if (dwSize < MAX_PATH * 2) {
				for (DWORD i = 0; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);
				LowerName[dwSize] = L'\0';
			}
		}

		DWORD dwSize = lstrlenW(szProcessName);
		if (dwSize < MAX_PATH * 2) {
			for (DWORD i = 0; i < dwSize; i++)
				LowerSearchName[i] = (WCHAR)tolower(szProcessName[i]);
			LowerSearchName[dwSize] = L'\0';
		}

		if (wcscmp(LowerName, LowerSearchName) == 0) {
			*dwProcId = Proc.th32ProcessID;
			*hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				wprintf(L"[!] OpenProcess failed: %d\n", GetLastError());
			break;
		}
	} while (Process32Next(hSnapshot, &Proc));

_EndOfFunction:
	if (hSnapshot != NULL)
		CloseHandle(hSnapshot);
	if (*dwProcId == 0 || *hProcess == NULL)
		return FALSE;
	return TRUE;
}

void InspectProc(LPWSTR processName) {
	DWORD dwProcId = 0;
	HANDLE hProcess = NULL;

	if (ProcEnum(processName, &dwProcId, &hProcess)) {
		wprintf(L"\nfound process: %s (PID: %lu)\n", processName, dwProcId);
		if (hProcess)
			CloseHandle(hProcess);
	}
	else {
		wprintf(L"process '%s' not found\n", processName);

		ProcessSuggestion suggestions[10];
		int suggestionCount = 0;
		FindSimilarProcesses(processName, suggestions, &suggestionCount, 10);

		if (suggestionCount > 0) {
			wprintf(L"did you mean:\n");
			for (int i = 0; i < suggestionCount && i < 5; i++) {
				wprintf(L"  - %s\n", suggestions[i].name);
			}
		}
	}
}

int wmain(int argc, wchar_t* argv[]) {
	PrintBanner();

	if (argc < 2) {
		wprintf(L"usage: %s [process name]", argv[0]);
		return -1;
	}

	if (wcscmp(argv[1], L"-i") == 0) {
		if (argc < 3) {
			wprintf(L"error: -i flag requires a process name\n");
			return -1;
		}
		InspectProc(argv[2]);
	}
	else {
		wprintf(L"unknown option: %ls\n", argv[1]);
		return -1;
	}

	return 0;
}