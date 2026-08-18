/**
 * bitlocker_windows_wmi.hpp — pure WMI-row -> BitLocker output-row mapping
 * for the bitlocker plugin's Windows leg.
 *
 * The acquisition call sites (bitlocker_plugin.cpp, _WIN32 branch) run two
 * WMI operations against root\CIMV2\Security\MicrosoftVolumeEncryption in
 * place of the old raw `manage-bde -status` popen:
 *   - a query enumerating Win32_EncryptableVolume (DeviceID, DriveLetter,
 *     ProtectionStatus) — one row per volume;
 *   - a per-volume GetConversionStatus() method call, returning its live
 *     encryption/conversion state and percentage.
 *
 * Everything downstream of those two raw WMI results is pure and lives
 * here so it is fixture-testable without a live WMI provider. This header
 * has no <windows.h>/COM dependency and takes plain
 * std::map<std::string, std::string> rows — the same shape
 * yuzu::shared::wmi::WmiRow aliases (agents/shared/wmi_bounded.hpp,
 * authored in parallel on PR3.3a), kept as an independent local alias here
 * so this header, and its test, compile and run on every host, not just
 * Windows.
 *
 * Output shape is frozen to the pre-migration `manage-bde -status` text
 * parser's 5-field row: `volume|<drive>|<conversion>|<pct_encrypted>|
 * <method>|<protection>`. `method` (BitLocker's "Encryption Method", e.g.
 * "XTS-AES 128") has no equivalent among the properties this migration's
 * query selects — Win32_EncryptableVolume::EncryptionMethod was
 * deliberately left out so the query stays the exact small surface this
 * migration specified — so it is honestly reported "unknown" rather than
 * fabricated, the same "never guess" convention bitlocker_macos_apfs.hpp
 * already follows for FileVault fields diskutil doesn't supply.
 */
#pragma once

#include <cctype>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::bitlocker::windows {

using WmiRow = std::map<std::string, std::string>;

/// One BitLocker-encryptable volume, as reported by Win32_EncryptableVolume.
struct EncryptableVolume {
    std::string device_id;             // e.g. "\\?\Volume{GUID}\" — WMI's own escaping
    std::string drive_letter;          // e.g. "C:"
    std::string protection_status_raw; // WMI ProtectionStatus, as a decimal string
};

/// Win32_EncryptableVolume::ProtectionStatus (MS docs): 0=Unprotected,
/// 1=Protected, 2=Unknown. Mapped to the same "Protection On"/"Protection
/// Off" phrasing manage-bde -status used, so an existing consumer parsing
/// this field sees familiar values despite the acquisition change.
inline std::string protection_status_text(const std::string& raw) {
    if (raw == "0")
        return "Protection Off";
    if (raw == "1")
        return "Protection On";
    return "Protection Unknown";
}

/// Win32_EncryptableVolume::GetConversionStatus's ConversionStatus out
/// param (MS docs): 0=FullyDecrypted, 1=FullyEncrypted,
/// 2=EncryptionInProgress, 3=DecryptionInProgress, 4=EncryptionPaused,
/// 5=DecryptionPaused. Mapped to manage-bde's own "Conversion Status" text.
inline std::string conversion_status_text(const std::string& raw) {
    if (raw == "0")
        return "Fully Decrypted";
    if (raw == "1")
        return "Fully Encrypted";
    if (raw == "2")
        return "Encryption In Progress";
    if (raw == "3")
        return "Decryption In Progress";
    if (raw == "4")
        return "Encryption Paused";
    if (raw == "5")
        return "Decryption Paused";
    return "Unknown";
}

/// The percentage-encrypted output field, from GetConversionStatus's
/// EncryptionPercentage out param. Rendered as "<N>%" when the value is a
/// plain non-negative integer (0-100 in practice); an unparseable or
/// absent value is reported "unknown" rather than a fabricated "0%".
inline std::string format_percentage(const std::string& raw) {
    if (raw.empty())
        return "unknown";
    for (char c : raw) {
        if (c < '0' || c > '9')
            return "unknown";
    }
    return raw + "%";
}

/// Parse the rows a run_bounded_wmi_query() over Win32_EncryptableVolume
/// returns into typed volume records. A row missing DeviceID is dropped —
/// there is nothing to key the follow-up GetConversionStatus call on.
/// Missing DriveLetter/ProtectionStatus are tolerated and reported
/// honestly (empty drive / "Protection Unknown").
inline std::vector<EncryptableVolume> parse_encryptable_volumes(const std::vector<WmiRow>& rows) {
    std::vector<EncryptableVolume> out;
    out.reserve(rows.size());
    for (const auto& row : rows) {
        auto id_it = row.find("DeviceID");
        if (id_it == row.end() || id_it->second.empty())
            continue;
        EncryptableVolume vol;
        vol.device_id = id_it->second;
        if (auto it = row.find("DriveLetter"); it != row.end())
            vol.drive_letter = it->second;
        if (auto it = row.find("ProtectionStatus"); it != row.end())
            vol.protection_status_raw = it->second;
        out.push_back(std::move(vol));
    }
    return out;
}

/// Build the WMI object path for a per-volume GetConversionStatus() method
/// call from its DeviceID, escaping the value for embedding inside a WQL
/// object-path string literal (every backslash doubled). DeviceID values
/// look like `\\?\Volume{GUID}\`, giving
/// `Win32_EncryptableVolume.DeviceID="\\\\?\\Volume{GUID}\\"`.
inline std::string build_volume_object_path(const std::string& device_id) {
    std::string escaped;
    escaped.reserve(device_id.size() * 2);
    for (char c : device_id) {
        if (c == '\\')
            escaped += "\\\\";
        else
            escaped += c;
    }
    return "Win32_EncryptableVolume.DeviceID=\"" + escaped + "\"";
}

/// One volume's live conversion state, decoded from a GetConversionStatus()
/// WMI method-call result row.
struct ConversionState {
    std::string conversion_text; // e.g. "Fully Encrypted"
    std::string percent_text;    // e.g. "100%" or "unknown"
};

/// A method-call result missing ConversionStatus/EncryptionPercentage, OR
/// carrying a non-zero ReturnValue (the WMI method itself failed even
/// though the COM call transported successfully), is reported honestly —
/// "Unknown" / "unknown" — never a fabricated "Fully Decrypted". Absent
/// ReturnValue is treated as failure too: a provider that omits it has not
/// affirmatively told us the call succeeded.
inline ConversionState parse_conversion_status(const WmiRow& row) {
    ConversionState state;
    if (auto it = row.find("ReturnValue"); it == row.end() || it->second != "0") {
        state.conversion_text = "Unknown";
        state.percent_text = "unknown";
        return state;
    }
    if (auto it = row.find("ConversionStatus"); it != row.end())
        state.conversion_text = conversion_status_text(it->second);
    else
        state.conversion_text = "Unknown";
    if (auto it = row.find("EncryptionPercentage"); it != row.end())
        state.percent_text = format_percentage(it->second);
    else
        state.percent_text = "unknown";
    return state;
}

/// Format one volume's output row, frozen to the pre-migration 5-field
/// shape (`volume|<drive>|<conversion>|<pct_encrypted>|<method>|
/// <protection>`); `method` is always "unknown" — see file header comment.
inline std::string format_volume_row(const EncryptableVolume& vol, const ConversionState& conv) {
    std::string drive = vol.drive_letter.empty() ? "unknown" : vol.drive_letter;
    return "volume|" + drive + "|" + conv.conversion_text + "|" + conv.percent_text +
           "|unknown|" + protection_status_text(vol.protection_status_raw);
}

/// Whether a WMI query/method-call error string indicates the caller lacks
/// the admin rights root\CIMV2\Security\MicrosoftVolumeEncryption requires
/// (that namespace is access-controlled — MS docs), rather than some other
/// failure (provider not registered, RPC server unavailable, etc).
/// Matched case-insensitively against the handful of phrasings COM/WMI
/// actually produce for E_ACCESSDENIED, so an unprivileged run can be
/// mapped to a typed "permission_denied" result instead of a generic
/// error — an operator sees WHY an unprivileged agent gets no BitLocker
/// data instead of a raw COM failure string.
inline bool is_permission_denied(const std::optional<std::string>& error) {
    if (!error.has_value())
        return false;
    std::string lower;
    lower.reserve(error->size());
    for (char c : *error)
        lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return lower.find("access is denied") != std::string::npos ||
           lower.find("access denied") != std::string::npos ||
           lower.find("0x80070005") != std::string::npos; // E_ACCESSDENIED
}

} // namespace yuzu::bitlocker::windows
