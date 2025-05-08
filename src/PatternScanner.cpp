// File: PatternScanner.cpp

#include "PatternScanner.h"
#include <sstream>      // For std::istringstream
#include <cctype>       // For std::isxdigit
#include <stdexcept>    // For std::exception
#include <windows.h>    // <<< THIS IS THE KEY INCLUDE for VirtualQuery, MEMORY_BASIC_INFORMATION, PAGE_* constants
#include <cstdio>       // For sprintf_s 

// --- Temporary LogDebug definition if you don't have one ---
#include <iostream> // Or your actual logging framework
void LogDebugP(const std::string& msg) { // No longer inline
    std::string full_msg = "PatternScan DEBUG: " + msg + "\n"; // Construct full message
    OutputDebugStringA(full_msg.c_str());                     // Call OutputDebugStringA
}
// --- End Temporary LogDebug ---


// Use the same namespace as in the header
namespace PatternScan
{
    bool ParseAOBString(const std::string& aob_str, std::vector<uint8_t>& out_bytes, std::vector<bool>& out_mask)
    {
        out_bytes.clear();
        out_mask.clear();
        std::string current_byte_str;
        std::istringstream iss(aob_str);
        std::string token;

        while (iss >> token)
        {
            if (token == "?" || token == "??")
            {
                out_bytes.push_back(0x00); // Placeholder byte
                out_mask.push_back(true);  // Mark as wildcard
            }
            else if (token.length() == 2 &&
                std::isxdigit(static_cast<unsigned char>(token[0])) &&
                std::isxdigit(static_cast<unsigned char>(token[1])))
            {
                try {
                    out_bytes.push_back(static_cast<uint8_t>(std::stoul(token, nullptr, 16)));
                    out_mask.push_back(false); // Not a wildcard
                }
                catch (const std::exception& e) {
                    LogDebugP("Error parsing AOB token '" + token + "': " + e.what());
                    return false; // Parsing error
                }
            }
            else
            {
                LogDebugP("Invalid AOB token encountered: '" + token + "'");
                return false; // Invalid token format
            }
        }

        return !out_bytes.empty(); // Success if we parsed at least one byte/wildcard
    }


    uintptr_t FindPattern(uintptr_t start_address, size_t region_size, const std::vector<uint8_t>& pattern_bytes, const std::vector<bool>& pattern_mask)
    {
        char logBuffer[512]; // Increased buffer size for more data

        if (pattern_bytes.empty() || pattern_bytes.size() != pattern_mask.size() || region_size < pattern_bytes.size()) {
            sprintf_s(logBuffer, sizeof(logBuffer), "FindPattern: Invalid input. Pattern size: %zu, Mask size: %zu, Region size: %zu",
                pattern_bytes.size(), pattern_mask.size(), region_size);
            LogDebugP(logBuffer);
            return 0;
        }

        const size_t pattern_size = pattern_bytes.size();
        const uint8_t* scan_start_ptr = reinterpret_cast<const uint8_t*>(start_address);
        const uint8_t* scan_end_ptr = (region_size >= pattern_size) ? (scan_start_ptr + region_size - pattern_size) : scan_start_ptr;

        sprintf_s(logBuffer, sizeof(logBuffer), "FindPattern: Scanning from 0x%p to 0x%p. Pattern size: %zu.",
            (void*)scan_start_ptr, (void*)scan_end_ptr, pattern_size);
        LogDebugP(logBuffer);

        // --- VITAL DEBUGGING ---
        // This is the address where your IDA and ASI logs say the pattern *should* be.
        // Make sure this g_GameBaseAddr from your logs is consistent if you restart the game.
        // If g_GameBaseAddr changes, this expected_find_addr will also change.
        // For current logs: g_GameBaseAddr = 0x00007FF622610000
        // Static offset = 0x68D1040
        uintptr_t expected_find_addr_debug = start_address + 0x68D1040;
        sprintf_s(logBuffer, sizeof(logBuffer), "FindPattern: EXPECTED match address for this run: 0x%p", (void*)expected_find_addr_debug);
        LogDebugP(logBuffer);
        // --- END VITAL DEBUGGING ---

        for (const uint8_t* current_addr_ptr = scan_start_ptr; current_addr_ptr <= scan_end_ptr; ++current_addr_ptr)
        {
            uintptr_t current_uint_addr = reinterpret_cast<uintptr_t>(current_addr_ptr);

            // --- VITAL DEBUGGING: Check memory at the exact expected location ---
            if (current_uint_addr == expected_find_addr_debug) {
                std::string memBytesStr = "FindPattern: At EXPECTED address 0x";
                char addrHex[20];
                sprintf_s(addrHex, "%p", (void*)current_uint_addr);
                memBytesStr += addrHex;
                memBytesStr += ". Memory bytes are: ";

                // Attempt to read and log pattern_size bytes
                // Use IsBadReadPtr or VirtualQuery for safety if crashes occur,
                // but for .text section, direct read should usually be fine.
                MEMORY_BASIC_INFORMATION mbi;
                bool can_read = true;
                if (VirtualQuery(current_addr_ptr, &mbi, sizeof(mbi)) == 0) {
                    memBytesStr += "[VirtualQuery failed]";
                    can_read = false;
                }
                else if (!(mbi.Protect & PAGE_EXECUTE_READ) && !(mbi.Protect & PAGE_READONLY) && !(mbi.Protect & PAGE_READWRITE)) {
                    memBytesStr += "[Not readable, Protect=" + std::to_string(mbi.Protect) + "]";
                    can_read = false;
                }

                if (can_read) {
                    for (size_t k = 0; k < pattern_size && k < 32; ++k) { // Log up to 32 bytes
                        char byteHex[4];
                        sprintf_s(byteHex, "%02X ", current_addr_ptr[k]);
                        memBytesStr += byteHex;
                    }
                }
                LogDebugP(memBytesStr);

                // Also log the pattern we are searching for at this point
                std::string patBytesStr = "FindPattern: Pattern bytes being searched: ";
                for (size_t k = 0; k < pattern_size; ++k) {
                    char byteHex[4];
                    sprintf_s(byteHex, "%02X ", pattern_bytes[k]);
                    patBytesStr += byteHex;
                }
                LogDebugP(patBytesStr);
            }
            // --- END VITAL DEBUGGING ---

            bool found = true;
            for (size_t i = 0; i < pattern_size; ++i)
            {
                if (!pattern_mask[i] && current_addr_ptr[i] != pattern_bytes[i])
                {
                    // If we are at the expected address, log the first mismatch encountered
                    if (current_uint_addr == expected_find_addr_debug) {
                        sprintf_s(logBuffer, sizeof(logBuffer), "FindPattern: MISMATCH at 0x%p, index %zu. Mem: 0x%02X, Pat: 0x%02X",
                            (void*)current_uint_addr, i, current_addr_ptr[i], pattern_bytes[i]);
                        LogDebugP(logBuffer);
                    }
                    found = false;
                    break;
                }
            }

            if (found) {
                sprintf_s(logBuffer, sizeof(logBuffer), "FindPattern: Pattern FOUND at 0x%p!", (void*)current_addr_ptr);
                LogDebugP(logBuffer);
                return current_uint_addr;
            }
        }

        LogDebugP("FindPattern: Pattern NOT FOUND after full scan.");
        return 0;
    }
}