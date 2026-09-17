# Changelog

Tất cả những thay đổi, cải tiến và tính năng mới của dự án **Audit-WindowsLicenseCompliance** sẽ được ghi chép chi tiết trong tệp tài liệu này.

Quy chuẩn phiên bản tuân theo [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v0.1.0] - 2026-09-17

### Giới Thiệu Phiên Bản Đầu Tiên (Initial Release)
Phiên bản phát hành đầu tiên của **Audit-WindowsLicenseCompliance (Enterprise Windows License Compliance & Piracy Forensics Toolkit)** - Bộ công cụ rà soát toàn diện tính tuân thủ bản quyền Windows, phát hiện các kỹ thuật bẻ khóa tinh vi và tự động đối soát Hóa đơn điện tử VAT doanh nghiệp.

Được phát triển và hiệu chuẩn chuyên sâu theo khung pháp lý thanh kiểm tra của Việt Nam:
* **Nghị định 341/2025/NĐ-CP**: Quy định xử phạt vi phạm hành chính trong lĩnh vực sở hữu trí tuệ, quyền tác giả, an toàn thông tin mạng và sử dụng phần mềm máy tính doanh nghiệp.
* **Nghị định 131/2013/NĐ-CP & Nghị định 14/2022/NĐ-CP**: Xử phạt vi phạm quyền tác giả và quyền liên quan.
* **Điều 225 Bộ luật Hình sự**: Tội xâm phạm quyền tác giả, quyền liên quan đối với pháp nhân thương mại.
* **Tiêu chuẩn Quốc tế ISO/IEC 19770**: Quản trị tài sản phần mềm doanh nghiệp (Software Asset Management - SAM).

---

### Tính Năng Nổi Bật (Key Features)

#### 1. Hệ Thống Điều Tra Pháp Y 14 Tầng (14 Forensic Audit Layers)
* **Tầng 1: Nền tảng Phần cứng & Ảo hóa (Hardware Platform)**:
  * Tự động nhận diện thiết bị vật lý vs Máy ảo (VMware, VirtualBox, Hyper-V, KVM, QEMU, Xen, Parallels).
  * Khẳng định nguyên tắc kỹ thuật: Máy ảo không thể sở hữu bản quyền OEM BIOS từ nhà sản xuất; việc dùng Generic Key vĩnh viễn trên VM là dấu hiệu bẻ khóa kỹ thuật số.
* **Tầng 2: Hệ thống Giấy phép SPP (Software Protection Platform)**:
  * Truy vấn chuyên sâu WMI/CIM qua `SoftwareLicensingProduct` và `SoftwareLicensingService`.
  * Bóc tách mã trạng thái bản quyền (`LicenseStatus`: Licensed, OOBGrace, NonGenuineGrace, Notification...).
  * Kiểm tra thời hạn giấy phép qua `slmgr.vbs /xpr` (nhận diện vĩnh viễn vs có thời hạn 180 ngày).
* **Tầng 3: Bóc tách Khóa Mặc định (Default Generic Product Keys Fingerprinting)**:
  * Tích hợp từ điển nhận diện đầy đủ các khóa Generic của Microsoft cho Windows 10/11: Pro (`3V66T`), Home (`8HVX7`), Home Single Language (`6F4BT`, `WT2RQ`), Enterprise (`8HV2C`), LTSC (`J462D`, `BHDCD`), Education (`RR888`, `7CFBY`) và khóa GVLK KMS (`T83GX`...).
  * Đối chiếu chéo ma trận: Khóa Generic vs OEM BIOS vs Máy ảo.
* **Tầng 4: Trích xuất Bảng ACPI BIOS MSDM Table**:
  * Đọc trực tiếp `OA3xOriginalProductKey` từ firmware bo mạch chủ phần cứng (Dell, HP, Lenovo, ThinkPad, Asus...).
  * Hỗ trợ doanh nghiệp khôi phục bản quyền hợp pháp gốc đi theo máy nếu bị thợ cài đè bản Windows lậu.
* **Tầng 5: Kiểm tra Chữ ký số Authenticode & File Integrity**:
  * Xác thực chữ ký số Microsoft Corporation trên các file cốt lõi: `sppc.dll`, `sppsvc.exe`, `slmgr.vbs`, `slwga.dll`, `sppcommdlg.dll`.
  * Phát hiện mọi hành vi vá nhị phân (binary patching) làm mất chữ ký hợp lệ của hệ điều hành.
* **Tầng 6: Đặc trị Kỹ thuật Bẻ khóa OHOOK**:
  * Phát hiện sự tồn tại của tệp DLL bẻ khóa `C:\Windows\System32\sppcs.dll`.
  * Rà soát Catalog Signature và DLL injection can thiệp vào `sppc.dll`.
* **Tầng 7: Điều tra Pháp y Dấu vết Kỹ thuật số MAS (HWID, KMS38, TSforge)**:
  * **PSReadLine Forensics**: Quét toàn bộ lịch sử dòng lệnh người dùng bằng `Select-String` (không giới hạn số dòng) tìm lệnh gọi `irm https://get.activated.win|iex`, `massgrave`, `gatherosstate`.
  * **Event Log 4104 (ScriptBlock Logging)**: Quét nhật ký thực thi mã nguồn PowerShell trong 180 ngày tìm dấu vết script kích hoạt lậu.
  * **DNS Client Cache**: Bóc tách bộ nhớ đệm DNS tìm tên miền phân phối crack (`get.activated.win`, `massgrave.dev`, `activated.win`, `idkey.massgrave.dev`, `msguides.com`).
  * **Prefetch Forensics**: Tự động kiểm tra cờ `EnablePrefetcher` trước khi rà soát tệp `GATHEROSSTATE.EXE-*.pf` và `CLIPUP.EXE-*.pf`.
  * **KMS38 Detection**: Nhận diện bẻ khóa KMS38 lợi dụng vé gia hạn tới năm 2038 (`GracePeriodRemaining > 5,000,000` phút).
  * **TSforge & Tokens.dat Anomaly**: Phát hiện các tệp backup tái tạo tokens (`tokens.dat.bak`, `tokens.dat.old`, `tokens.bar`), cảnh báo dung lượng `tokens.dat < 500 KB`, rà soát can thiệp Registry `HKLM:\SYSTEM\WPA` và gia hạn lậu RDS GracePeriod.
* **Tầng 8: SppExtComObjHook & Driver Bẫy Mạng (WinDivert)**:
  * Phát hiện thư viện hook `SppExtComObjHook.dll`, `SppExtComObjPatcher.dll`.
  * Quét driver bắt gói tin mạng ngầm của Ratiborus/AAct: `windivert64.sys`, `windivert32.sys`.
* **Tầng 9: Registry IFEO Debugger & Tính Toàn Vẹn Dịch Vụ SPPSVC**:
  * Kiểm tra cấu hình `Image File Execution Options\SppExtComObj.exe` và `osppsvc.exe` bị gán Debugger chuyển hướng.
  * Giám sát dịch vụ bảo vệ bản quyền cốt lõi `sppsvc`: Báo động đỏ nếu dịch vụ bị chuyển sang `Disabled` hoặc bị gỡ bỏ hoàn toàn (đặc trưng Chew-WGA / RemoveWAT).
* **Tầng 10: Rà soát Máy chủ KMS & Quét Lắng nghe Cổng TCP 1688 Cục bộ**:
  * **Generic KMS Listener**: Quét trực tiếp `Get-NetTCPConnection -LocalPort 1688 -State Listen` trên máy trạm, truy vết chính xác PID và đường dẫn tiến trình (bắt trọn mọi emulator: vlmcsd, py-kms, KMSpico, KMSAuto, HEU KMS).
  * Danh sách đen hơn 30 máy chủ KMS công cộng hoạt động tại Châu Á và quốc tế (`kms.msguides.com`, `kms.digiboy.ir`, `kms.cangshui.net`, `kms.senbe.cn`, `kms.loli.best`...).
  * Cảnh báo máy tính Workgroup không gia nhập Active Directory Domain nhưng lại kích hoạt qua KMS ngoài.
* **Tầng 11: Rà soát Kho Công Cụ Bẻ Khóa Đa Dòng Trên Ổ Cứng**:
  * Quét thư mục và tệp thực thi của: **KMSpico**, **KMSAuto Net/Lite/++**, **AAct Portable**, **ConsoleAct**, **W10 Digital Activation**, **Microsoft Toolkit**, **HEU KMS Activator**, **KMS-R@1n**, **Daz SLIC Loader** (`grldr`, `slic.sys`), **WatGsp** (`watadmin.exe`).
  * Quét các script kích hoạt lậu tự động: `SetupComplete.cmd`, `ErrorHandler.cmd`, `oobe.cmd`.
* **Tầng 12: Tác Vụ Lên Lịch Tự Động Định Kỳ (Scheduled Tasks Re-arm)**:
  * Quét danh mục Scheduled Tasks tìm tác vụ duy trì kích hoạt chu kỳ 7-180 ngày: `AutoKMS`, `KMSpico`, `KMSAuto`, `AAct`, `AutoPico`, `HEU`, `CleanKMS`, `Ratiborus`, `W10Digital`, `SppExtComObj`.
* **Tầng 13: Can Thiệp Windows Defender & Tệp HOSTS**:
  * Quét danh sách loại trừ ngoại lệ của Windows Defender (`Get-MpPreference` `ExclusionPath` và `ExclusionProcess`) tìm đường dẫn hacktool được miễn quét virus.
  * Kiểm tra tệp `hosts` phát hiện hành vi chuyển hướng hoặc chặn các domain xác thực của Microsoft (`sls.microsoft.com`, `licensing.mp.microsoft.com`...).
* **Tầng 14: ĐỐI SOÁT HÓA ĐƠN ĐIỆN TỬ VAT THỰC TẾ (Burden of Proof)**:
  * Hỗ trợ 2 nguồn nạp chứng từ: REST API nội bộ doanh nghiệp (`-InvoiceApiUrl`) hoặc Tệp cục bộ JSON/CSV (`-InvoiceFile`).
  * Cơ chế chống False Positive thông minh (`Test-IsPlaceholderInvoice`): Tự động phát hiện và ngăn chặn việc gán nhầm dữ liệu mẫu mặc định (`"CÔNG TY DOANH NGHIỆP CỦA BẠN"`, MST mẫu).
  * Quy tắc khớp 2 vòng: Vòng 1 khớp đích danh phần cứng (Serial / Service Tag, Hostname); Vòng 2 khớp gói tập trung doanh nghiệp (`ALL_ENTERPRISE_POOL`) với ràng buộc máy phải gia nhập Domain hoặc khớp `-ExpectedTaxId`.
  * Cảnh báo Channel Mismatch: Hóa đơn mua CSP/Volume nhưng máy kích hoạt khóa Generic Retail.

---

#### 2. Chuyên Đề Pháp Y Bản Windows Mod / Ghost / Lite OS / Custom ISO
Phát hiện toàn diện các bản Windows đã qua can thiệp mã nguồn không chính thức (Việt Nam & Quốc tế) qua 5 chiều dữ liệu:
* **Deep Registry Branding**: Bóc tách 10 trường metadata trong `CurrentVersion` & `OEMInformation` đối chiếu từ điển hơn 35 tác giả/thương hiệu mod:
  * *Việt Nam*: Lê Hà IT, Khát Máu, Song Ngọc, Thuận Nguyễn, 21CD, PhanMemAZ, TIMT, TranBao, HSSM, Vforum, VN-Zoom, Ghoster, GhostViet.
  * *Quốc tế*: Ghost Spectre (SuperLite, Compact), ReviOS, AtlasOS, Tiny10, Tiny11 (NTDEV), GGOS, FoxOS, WinterOS, KernelOS, ReplayOS, Windows X-Lite (fbconan), Rectify11, AME Wizard / Ameliorated, Black Edition.
* **Unattended Setup XML Forensics**: Bóc tách `Panther\unattend.xml`, `sysprep\unattend.xml`, `C:\Autounattend.xml` phát hiện lệnh kích hoạt ngầm `AutoLogon`, `FirstLogonCommands`, `RunSynchronousCommand`.
* **Mod Toolboxes & Shell Injectors**: Phát hiện các thư mục `C:\GHOST`, `GhostToolbox`, `C:\Atlas`, `C:\ReviOS`, `AME Wizard` và các công cụ Start Menu nhúng ngầm `StartAllBack`, `StartIsBack`.
* **Gutted System Services Anomaly**: Phát hiện dịch vụ **Windows Update (`wuauserv`)** bị xóa sổ khỏi Registry hoặc ép `Disabled` vĩnh viễn; dịch vụ **Windows Defender (`WinDefend`)** bị gỡ bỏ.
* **Policy Tampering**: Phát hiện chính sách User Account Control (UAC) bị tắt cứng (`EnableLUA = 0`).

---

#### 3. Tự Động Hóa Quản Trị & Đa Dạng Hóa Đầu Ra Báo Cáo
* **Giao diện Console Trực quan**: Hiển thị màu sắc phân cấp rủi ro (PASSED - Xanh lá, WARNING - Tím, SUSPICIOUS - Vàng, FAILED - Đỏ) kèm bảng tổng kết và chỉ dẫn hành động pháp lý.
* **Báo cáo HTML Chuyên Nghiệp (`-ExportHtml`)**: Thiết kế giao diện hiện đại chuẩn báo cáo kiểm toán doanh nghiệp, hiển thị banner đánh giá, bảng thông tin thiết bị, khu vực chứng từ hóa đơn VAT và chi tiết 14 tầng kỹ thuật.
* **Báo cáo JSON (`-ExportJson`)**: Cấu trúc phân cấp đầy đủ chi tiết phục vụ tích hợp trực tiếp vào hệ thống giám sát SIEM, Splunk, ElasticSearch, Wazuh.
* **Báo cáo CSV Hàng Loạt (`-ExportCsv`)**: Hỗ trợ xuất và ghi nối tiếp (append mode) dữ liệu toàn bộ máy trạm vào file bảng tính tập trung.
* **Chế độ Chạy Ngầm (`-Quiet`)**: Chạy hoàn toàn tĩnh lặng không xuất màn hình console, tối ưu cho Active Directory GPO Startup Scripts, Microsoft Intune, SCCM, Datto, NinjaRMM.
* **Mã Thoát Chuẩn Hóa (Exit Codes)**:
  * `0`: **GENUINE_COMPLIANT** (Bản quyền hợp lệ, sạch crack, đối soát hóa đơn VAT thành công 100%).
  * `1`: **WARNING_MISSING_INVOICE / SUSPICIOUS_UNVERIFIED** (Máy sạch kỹ thuật nhưng thiếu hóa đơn đối ứng hoặc dùng Volume KMS ngoài).
  * `2`: **NON_COMPLIANT_UNLICENSED** (Windows chưa kích hoạt hoặc đang trong thời gian dùng thử).
  * `3`: **CRITICAL_PIRATED_CRACKED** (Phát hiện công cụ crack MAS, HWID, KMS, Ohook, Win Mod hoặc file hệ thống bị vá).
  * Đồng bộ tự động với `$global:LASTEXITCODE` và `%ERRORLEVEL%`.

---

### Các Tệp Tin Trong Bản Phát Hành
* `Audit-WindowsLicenseCompliance.ps1`: Engine kiểm toán chính (PowerShell 5.1+, mã hóa UTF-8 với BOM, tương thích Windows 10, 11, Windows Server 2016-2025).
* `invoices.json`: Tệp mẫu dữ liệu hóa đơn điện tử VAT dạng JSON.
* `invoices.csv`: Tệp mẫu dữ liệu hóa đơn điện tử VAT dạng CSV (chỉnh sửa bằng Excel).
* `README.md`: Tài liệu hướng dẫn sử dụng chuyên sâu, bối cảnh pháp lý và ma trận bẻ khóa.
* `CHANGELOG.md`: Nhật ký phát triển và ghi chép thay đổi phiên bản.
* `LICENSE`: Giấy phép mã nguồn mở MIT License.
* `photos/`: Hình ảnh minh họa hero banner, giao diện console thực thi và mẫu báo cáo HTML kiểm toán đạt chuẩn.
