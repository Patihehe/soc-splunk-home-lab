# BÁO CÁO SỰ CỐ AN NINH MẠNG

### Security Incident Report

|  |  |
| :---- | :---- |
| **Mã sự cố (Incident ID)** | INC-2026-001 |
| **Ngày phát hiện** | \[vd 2026-06-08\] |
| **Analyst** | Vũ Bá Thi |
| **Mức độ (Severity)** | **High / Critical** |
| **Trạng thái** | Đã điều tra — Mô phỏng lab (Resolved) |
| **Phân loại** | Multi-stage intrusion — Credential Access, Persistence, Privilege Escalation |

## 1\. Tóm tắt điều hành (Executive Summary)

Hệ thống giám sát SOC (Splunk) phát hiện một chuỗi tấn công đa giai đoạn nhắm vào máy trạm `[DESKTOP-H7GVTPR]`. Lúc 13:43, kẻ tấn công brute force tài khoản trên DESKTOP-H7GVTPR (nhiều lần đăng nhập thất bại — Security 4625). Sau khi có chỗ đứng, lúc 13:53 chúng chạy PowerShell tải payload từ mạng (IEX DownloadString — T1059.001). Để duy trì truy cập, lúc 13:55 chúng cài hai cơ chế persistence: ghi Registry Run key (T1547.001) và tạo scheduled task "AtomicTask" (T1053.005). Lúc 13:56 chúng leo thang đặc quyền — tạo tài khoản mới và thêm vào nhóm Administrators (Security 4720 \+ 4732 — T1136.001). Từ 13:57 đến 14:11 chúng dump bộ nhớ LSASS ba lần bằng kỹ thuật comsvcs.dll LOLBin để đánh cắp thông tin xác thực (T1003.001). Cuối cùng, lúc 15:09 chúng do thám tài khoản và nhóm bằng net.exe (T1087.001) nhằm chuẩn bị mở rộng tấn công.

## 2\. Hệ thống & tài khoản bị ảnh hưởng

| Loại | Giá trị |
| :---- | :---- |
| Máy bị ảnh hưởng | `[DESKTOP-H7GVTPR]` (192.168.13.20) |
| Tài khoản bị nhắm (brute force) | `[Administrator]`, `[fakeadmin]` |
| Tài khoản độc hại được tạo | `[T1136.001_Admin]` |
| Nguồn tấn công | `[Kali — 192.168.13.30]` |

## 3\. Timeline sự kiện (Kill Chain)

*Dán kết quả truy vấn timeline (Phần C — Tuần 5\) và rút gọn thành bảng:*

| Thời gian | Giai đoạn | Technique | Hành động quan sát |
| :---- | :---- | :---- | :---- |
| `13:43`  | Credential Access | T1110 | `Nhiều lần đăng nhập thất bại (4625)`  |
| `13:53`  | Execution | T1059.001 | `PowerShell IEX DownloadString`  |
| `13:55`  | Persistence | T1547.001 | Ghi Registry Run key (reg.exe)  |
| `13:55`  | Persistence | T1053.005 | `schtasks /create AtomicTask`  |
| `13:56`  | Priv-Esc/Persistence | T1136.001 | Tạo user \+ thêm Administrators (4720/4732) ) |
| `13:57–14:11`  | Credential Access | T1003.001 | `rundll32 comsvcs.dll MiniDump → lsass_dump.dmp (×3)`  |
| `15:09`  | Discovery | T1087.001 | `net user, net localgroup administrators`  |

## 4\. Map MITRE ATT\&CK

| Technique | ID | Tactic | Phát hiện bởi |
| :---- | :---- | :---- | :---- |
| Brute Force | T1110 | Credential Access | Rule 1 (Security 4625\) |
| PowerShell | T1059.001 | Execution | Rule 2 (Sysmon EID 1\) |
| Registry Run Key | T1547.001 | Persistence | Rule 3 (Sysmon EID 13\) |
| Scheduled Task | T1053.005 | Persistence | Rule 4 (Sysmon EID 1\) |
| Create Account | T1136.001 | Persistence | Rule 5 (Security 4720/4732) |
| LSASS Dumping | T1003.001 | Credential Access | Rule 6 (Sysmon EID 1/11) |
| Account Discovery | T1087.001 | Discovery | Rule 7 (Sysmon EID 1\) |

## 5\. Chỉ số xâm phạm (IOCs)

Tài khoản độc hại    : T1136.001\_Admin  
File dump LSASS      : C:\\Windows\\Temp\\lsass\_dump.dmp  
Registry persistence : HKCU\\...\\CurrentVersion\\Run\\AtomicRedTeam  
Scheduled task       : AtomicTask  
Tiến trình bất thường: rundll32.exe comsvcs.dll MiniDump (dump LSASS)  
                     : powershell.exe ... IEX DownloadString  
Account bị brute     : Administrator, fakeadmin

## 6\. Đánh giá tác động

- **Tính bí mật (Confidentiality):** CAO — LSASS bị dump → credential trong bộ nhớ có thể bị đánh cắp (pass-the-hash, lateral movement).  
- **Tính toàn vẹn (Integrity):** tài khoản admin trái phép được tạo → kẻ tấn công có quyền điều khiển máy.  
- **Tính sẵn sàng (Availability):** chưa bị ảnh hưởng trong kịch bản này.

## 7\. Khuyến nghị (Containment & Hardening)

**Ngăn chặn ngay:**

- Vô hiệu hóa/xóa tài khoản `[T1136.001_Admin]`.  
- Xóa Run key và scheduled task độc hại.  
- Reset mật khẩu các tài khoản trên máy bị dump LSASS (credential coi như đã lộ).

**Phòng thủ dài hạn:**

- Bật **Account Lockout Policy** (đã chứng minh chặn được brute force Administrator).  
- Bật **Audit Process Creation (4688)** \+ Sysmon **EID 10** để bắt truy cập LSASS trực tiếp.  
- Hạn chế **SeDebugPrivilege**; bật Credential Guard.  
- Giám sát LOLBins (`rundll32`, `comsvcs.dll`) — như Rule 6 đã làm.

## 8\. Bài học (Lessons Learned)

- Detection theo **ngưỡng/hành vi** (brute force, discovery burst) phải dùng **Scheduled alert**, không dùng Real-time — vì cần gom đếm theo cửa sổ thời gian.  
- **Giảm false positive** là phần khó nhất: rule Registry Run key ban đầu dính cả "Runtime" và Edge AutoLaunch → phải thêm bộ lọc loại trừ.  
- Phủ **nhiều biến thể** của một kỹ thuật (procdump *và* comsvcs LOLBin cho LSASS) mạnh hơn nhiều so với bắt đúng một công cụ.

*Báo cáo này được tạo trong môi trường lab mô phỏng phục vụ học tập. Mọi tấn công do chính analyst thực hiện có kiểm soát.*  
