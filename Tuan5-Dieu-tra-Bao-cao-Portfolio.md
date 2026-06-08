# TUẦN 5 — Điều tra, Báo cáo sự cố & Hoàn thiện Portfolio

> **Đích đến:** chuyển từ "người dựng lab" thành **SOC analyst biết kể chuyện**. Lấy các alert đã bắn → điều tra → dựng lại toàn bộ chuỗi tấn công → viết báo cáo sự cố → đóng gói tất cả thành portfolio GitHub gây ấn tượng.

**Đầu ra tuần này:**
- [ ] 1 cuộc điều tra hoàn chỉnh (alert → timeline → kết luận)
- [ ] 1 báo cáo sự cố (incident report) — dùng file `Bao-cao-su-co-MAU.md`
- [ ] 1 MITRE ATT&CK Navigator layer — import file `mitre-navigator-layer.json`
- [ ] 1 README portfolio hoàn chỉnh đẩy lên GitHub — dùng file `README-portfolio.md`

---

## PHẦN A — Tư duy điều tra của một SOC Analyst (đọc trước)

Detection (Tuần 4) chỉ là **chuông báo**. Việc của analyst bắt đầu *sau khi* chuông kêu. Quy trình chuẩn (vòng đời ứng phó sự cố — NIST/SANS):

```
Phát hiện → Phân loại (Triage) → Điều tra → Khoanh vùng (Scope)
   → Đánh giá tác động → Ngăn chặn/Khắc phục → Báo cáo & Bài học
```

Với mỗi alert, analyst trả lời **6 câu hỏi** (5W1H):
| Câu hỏi | Tìm gì trong log |
|---|---|
| **What** — chuyện gì xảy ra? | Loại sự kiện, technique |
| **When** — khi nào? | `_time` — mốc đầu/cuối |
| **Where** — máy/tài khoản nào? | `host`, `Account_Name` |
| **Who** — nguồn tấn công? | IP nguồn, parent process |
| **How** — bằng cách nào? | `CommandLine`, chuỗi process |
| **Impact** — hậu quả? | Account bị tạo, cred bị dump... |

**True positive hay false positive?** Câu hỏi đầu tiên của mọi triage. Trong lab này tất cả là TP (bạn tự tấn công), nhưng trong báo cáo hãy ghi rõ *lý do* kết luận TP (vd "command line chứa `comsvcs.dll MiniDump` nhắm PID của lsass — không có lý do hợp lệ nào").

---

## PHẦN B — Điều tra thực hành trong Splunk

Ta sẽ điều tra **bắt đầu từ alert nghiêm trọng nhất** và lần ngược ra toàn bộ chiến dịch. Chọn alert `[High] New Admin Account Created (T1136.001)` làm điểm khởi đầu (kẻ tấn công vừa tạo admin = dấu hiệu xâm nhập sâu).

### Bước 1 — Triage: alert này nói gì?
```spl
index=endpoint (EventCode=4720 OR EventCode=4732)
| table _time, host, EventCode, Account_Name
| sort _time
```
→ Ghi lại: **tên account bị tạo** (vd `T1136.001_Admin`), **máy nào** (`host`), **thời điểm**. Thấy 4720 (tạo user) rồi 4732 (thêm vào Administrators) sát nhau = *tạo user xong promote thẳng lên admin* — hành vi rất đáng ngờ.

### Bước 2 — Pivot theo host: máy này còn xảy ra gì khác?
```spl
index=endpoint host="DESKTOP-H7GVTPR" earliest=-24h
| timechart span=10m count by EventCode
```
→ Nhìn các đỉnh hoạt động. Một máy bình thường không đột nhiên có cụm 4625 (đăng nhập thất bại) + 4720 + nhiều EID 1 lạ trong vài phút. Cụm bất thường này chính là **cửa sổ tấn công** — khoanh nó lại.

### Bước 3 — Soi chuỗi tiến trình (process tree)
```spl
index=endpoint source="*Sysmon*" EventCode=1 host="DESKTOP-H7GVTPR"
| table _time, ParentImage, Image, CommandLine, User
| sort _time
```
→ Đọc cột `ParentImage → Image`: ai sinh ra ai. Vd `cmd.exe → powershell.exe (IEX DownloadString...)` cho thấy chuỗi thực thi. Đây là bằng chứng "kể chuyện" mạnh nhất.

### Bước 4 — Truy nguồn brute force (Who)
```spl
index=endpoint EventCode=4625
| stats count, values(Logon_Type) as kieu_logon by Account_Name, ComputerName
| sort - count
```
→ Account nào bị nhắm, bao nhiêu lần, Logon Type 3 (network) = tấn công qua mạng/SMB. Đây là **điểm khởi đầu** của cả chiến dịch (Initial Access / Credential Access).

### Bước 5 — Gom IOC (Indicators of Compromise)
Liệt kê mọi "dấu vân tay" của kẻ tấn công để đưa vào báo cáo:
| Loại IOC | Cách lấy |
|---|---|
| Account độc hại | `T1136.001_Admin` (từ 4720) |
| File dump | `C:\Windows\Temp\lsass_dump.dmp` (từ EID 11/CommandLine) |
| Registry key | giá trị Run "AtomicRedTeam" (từ EID 13 `TargetObject`/`Details`) |
| Scheduled task | tên task "AtomicTask" (từ CommandLine `schtasks`) |
| Account bị brute | `Administrator`/`fakeadmin` (từ 4625) |

---

## PHẦN C — Dựng lại TOÀN BỘ chuỗi tấn công (kill-chain timeline)

Đây là câu **đắt giá nhất** của cả điều tra: gom mọi technique về 1 dòng thời gian, gắn nhãn MITRE. Chạy với Time Range đủ rộng (vd Last 24 hours):

```spl
index=endpoint (EventCode=4625 OR EventCode=4720 OR EventCode=4732 OR EventCode=1 OR EventCode=13 OR EventCode=11)
| eval ky_thuat=case(
    EventCode=4625, "T1110 — Brute Force",
    EventCode=1 AND like(CommandLine,"%DownloadString%"), "T1059.001 — Malicious PowerShell",
    EventCode=13 AND like(TargetObject,"%CurrentVersion%Run%"), "T1547.001 — Registry Run Key",
    EventCode=1 AND like(CommandLine,"%schtasks%") AND like(CommandLine,"%create%"), "T1053.005 — Scheduled Task",
    EventCode=4720, "T1136.001 — Create Account",
    EventCode=4732, "T1136.001 — Add to Admin Group",
    EventCode=1 AND ((like(CommandLine,"%procdump%") AND like(CommandLine,"%lsass%")) OR (like(CommandLine,"%comsvcs%") AND like(CommandLine,"%MiniDump%"))), "T1003.001 — LSASS Dump",
    EventCode=11 AND like(TargetFilename,"%lsass%.dmp"), "T1003.001 — LSASS Dump File",
    EventCode=1 AND (like(CommandLine,"%net user%") OR like(CommandLine,"%net localgroup%") OR like(CommandLine,"%whoami%") OR like(CommandLine,"%quser%")), "T1087.001 — Account Discovery"
  )
| where isnotnull(ky_thuat)
| sort _time
| table _time, host, ky_thuat, Image, CommandLine, Account_Name, TargetObject, TargetFilename
```

> ⚠️ Nếu tên field khác chút (tùy add-on), chỉnh cho khớp với rule Tuần 4 của bạn — bạn đã biết chúng rồi (`TargetObject`, `CommandLine`, `Account_Name`...).

**Diễn giải timeline thành câu chuyện tấn công** (ghi vào báo cáo, ánh xạ giai đoạn kill chain):

| Giai đoạn | Technique | Điều kẻ tấn công làm |
|---|---|---|
| Initial/Credential Access | T1110 | Brute force tài khoản qua SMB |
| Execution | T1059.001 | Chạy PowerShell tải payload từ mạng |
| Persistence | T1547.001 | Cài Registry Run key để tự khởi động |
| Persistence | T1053.005 | Tạo scheduled task duy trì truy cập |
| Privilege Escalation/Persistence | T1136.001 | Tạo user mới + đẩy lên admin |
| Credential Access | T1003.001 | Dump LSASS lấy credential |
| Discovery | T1087.001 | Liệt kê tài khoản/nhóm để mở rộng |

📸 **Chụp timeline này** — nó cho thấy bạn không chỉ bắt từng cảnh báo lẻ mà **dựng lại được cả chiến dịch**. Đây là kỹ năng cốt lõi của SOC analyst (correlation + storytelling).

---

## PHẦN D — Viết báo cáo sự cố (Incident Report)

Mở file **`Bao-cao-su-co-MAU.md`** mình tạo kèm — đã có sẵn cấu trúc chuẩn SOC và điền mẫu theo lab của bạn. Việc của bạn: thay số liệu/thời gian/ảnh thật vào.

Một báo cáo sự cố tốt gồm:
1. **Executive Summary** — 3–4 câu cho người không kỹ thuật (sếp đọc).
2. **Phân loại & mức độ** — Severity, trạng thái.
3. **Hệ thống bị ảnh hưởng** — host, tài khoản.
4. **Timeline sự kiện** — bảng từ Phần C.
5. **Map MITRE ATT&CK** — bảng technique/tactic.
6. **IOCs** — danh sách từ Phần B bước 5.
7. **Đánh giá tác động** — cái gì bị xâm phạm.
8. **Khuyến nghị** — cách phát hiện/ngăn chặn lần sau.
9. **Bài học** (lessons learned).

> **Mẹo ăn điểm phỏng vấn:** phần Khuyến nghị thể hiện bạn nghĩ về *phòng thủ*, không chỉ phát hiện. Vd: "Bật Account Lockout Policy đã chặn brute force Administrator"; "Bật `Audit Process Creation` + Sysmon EID 10 để bắt LSASS access trực tiếp"; "Hạn chế SeDebugPrivilege".

---

## PHẦN E — MITRE ATT&CK Navigator layer

Mình tạo sẵn file **`mitre-navigator-layer.json`** với đủ 7 technique đã tô màu.

1. Vào `https://mitre-attack.github.io/attack-navigator/`
2. **Open Existing Layer → Upload from local** → chọn `mitre-navigator-layer.json`
3. 7 ô technique của bạn sẽ sáng màu trên ma trận.
4. 📸 Chụp toàn ma trận → đưa vào README.

→ "Bản đồ độ phủ phát hiện" này cho thấy trực quan bạn cover 6 tactic của kill chain. Rất "đẹp CV".

---

## PHẦN F — Đóng gói Portfolio lên GitHub

Mở file **`README-portfolio.md`** — template hoàn chỉnh, chỉ cần điền và chèn ảnh.

**Tổ chức repo gợi ý:**
```
soc-splunk-home-lab/
├── README.md                  ← từ README-portfolio.md
├── screenshots/               ← tất cả ảnh đã chụp
│   ├── 01-architecture.png
│   ├── 02-log-collection.png
│   ├── 03-dashboard.png
│   ├── 04-triggered-alerts-7.png   ← ảnh "ngôi sao"
│   ├── 05-attack-timeline.png
│   └── 06-mitre-navigator.png
├── detection-rules/           ← 7 file .spl (copy từ Tuần 4)
├── reports/
│   └── incident-report.md     ← báo cáo của bạn
└── mitre/
    └── navigator-layer.json
```

**Thứ tự ưu tiên ảnh trong README** (nhà tuyển dụng lướt nhanh):
1. Sơ đồ kiến trúc lab (3 VM, subnet).
2. **Triggered Alerts 7/7** ← để cao nhất phần Detection.
3. Attack timeline (Phần C).
4. MITRE Navigator layer.
5. 1–2 ảnh detection rule + kết quả.

**Đẩy lên GitHub:**
```bash
git init
git add .
git commit -m "SOC Home Lab: Splunk detection engineering, 7 MITRE techniques"
git branch -M main
git remote add origin https://github.com/<username>/soc-splunk-home-lab.git
git push -u origin main
```

> ⚠️ Trước khi push: kiểm tra không lẫn IP công khai thật, mật khẩu, hay license key Splunk trong ảnh/file.

---

## Mốc hoàn thành Tuần 5 (và cả project)
- [ ] Điều tra xong 1 alert → ra toàn bộ kill chain (Phần B + C)
- [ ] Chụp ảnh timeline tấn công
- [ ] Viết xong báo cáo sự cố (`Bao-cao-su-co-MAU.md` → bản của bạn)
- [ ] Import + chụp MITRE Navigator layer
- [ ] README hoàn chỉnh + repo có cấu trúc + đủ ảnh
- [ ] Push lên GitHub, link repo sẵn sàng dán vào CV

**Xong tuần này = bạn có một portfolio SOC hoàn chỉnh:** xây lab → thu log → viết detection → bắt tấn công thật → điều tra → báo cáo. Đây đúng là một vòng đời SOC thu nhỏ — thứ phân biệt ứng viên "đã học" với ứng viên "đã làm".

---

## Gợi ý nói trong phỏng vấn (1 câu chốt)
> *"Em tự xây một SOC home lab bằng Splunk, viết 7 detection rule map MITRE ATT&CK, tự mô phỏng chuỗi tấn công AD đa giai đoạn rồi điều tra dựng lại toàn bộ kill chain và viết báo cáo sự cố. Phần khó nhất em học được là tinh chỉnh rule để giảm false positive — ví dụ rule Registry Run key ban đầu dính cả Edge và chuỗi 'Runtime'."*

Câu này chạm đúng 3 thứ nhà tuyển dụng SOC muốn: **detection engineering, hiểu MITRE, và tư duy giảm false positive**.
