<p align="center">
  <img src="./photos/hero.png" alt="Audit Windows License Compliance Hero Banner" width="100%">
</p>

# Enterprise Windows License Compliance & Piracy Forensics Toolkit

> Bộ Công Cụ **Rà Soát Tuân Thủ Bản Quyền Windows** & **Đối Soát Hóa Đơn VAT Doanh Nghiệp**.
>
> **Tác giả / Author:** [@uzii2208](https://github.com/uzii2208)  
> **Căn cứ pháp lý:** Nghị định 341/2025/NĐ-CP | Nghị định 131/2013/NĐ-CP | Nghị định 14/2022/NĐ-CP | Điều 225 BLHS.  
> **Tiêu chuẩn quốc tế:** ISO/IEC 19770 (Software Asset Management - SAM).

---

## Giới Thiệu & Bối Cảnh Pháp Lý Doanh Nghiệp

Theo quy định mới tại **Nghị định 341/2025/NĐ-CP** (quy định xử phạt vi phạm hành chính trong lĩnh vực sở hữu trí tuệ, quyền tác giả, quyền liên quan, an toàn thông tin mạng và sử dụng phần mềm máy tính doanh nghiệp):
1. **Nghĩa vụ chứng minh tính hợp pháp**: Khi đoàn Thanh tra liên ngành (Bộ TT&TT, Bộ KH&CN, Cục C05/PA05 Bộ Công an) kiểm tra, màn hình Windows hiển thị *"Windows is activated"* **hoàn toàn không có giá trị pháp lý** nếu doanh nghiệp không xuất trình được **Hóa đơn tài chính hợp pháp (Hóa đơn điện tử VAT)** hoặc Hợp đồng cấp phép từ Microsoft/Đối tác ủy quyền.
2. **Hành vi sử dụng công cụ bẻ khóa**: Việc sử dụng các công cụ crack (Ohook, KMS giả lập, KMSpico, MAS...) bị coi là hành vi cố ý can thiệp trái phép vào mã nguồn hệ điều hành, vi phạm quyền tác giả với mức xử phạt hành chính lên tới hàng trăm triệu đồng, buộc tiêu hủy bản sao lậu, công khai xin lỗi và có nguy cơ bị truy cứu trách nhiệm hình sự đối với pháp nhân thương mại.
3. **Bẫy lệch phiên bản (Edition Mismatch)**: Doanh nghiệp mua laptop có sẵn Windows Home OEM (thể hiện trên hóa đơn mua máy), nhưng kỹ thuật viên cài đè bản Windows Pro lậu -> **Bị xử phạt hành chính ngay trên từng thiết bị vi phạm**.

Bộ công cụ **Audit-WindowsLicenseCompliance** ra đời nhằm giúp đội ngũ Quản trị IT, Kế toán và Pháp chế doanh nghiệp chủ động rà soát 100% thiết bị, phát hiện các dấu vết bẻ khóa tinh vi và tự động liên kết hóa đơn VAT trước khi có đợt thanh kiểm tra chính thức.

---

## 12 Tầng Phân Tích Kỹ Thuật Chuyên Sâu

| # | Hạng mục rà soát | Cơ chế phân tích điều tra pháp y (Forensics) | Dấu hiệu phát hiện vi phạm / Rủi ro |
|---|---|---|---|
| **1** | **SPP Licensing Subsystem** | Truy vấn trực tiếp CIM/WMI `SoftwareLicensingProduct` & `SoftwareLicensingService` | • `LicenseStatus != 1` (Chưa kích hoạt, Grace Period)<br>• Kênh cấp phép bất thường so với thực tế mua sắm |
| **2** | **ACPI BIOS MSDM Table** | Đọc `OA3xOriginalProductKey` từ bo mạch chủ phần cứng (Dell, HP, ThinkPad...) | • Bóc tách key OEM gốc theo máy để khôi phục bản quyền hợp pháp miễn phí nếu bị thợ cài đè Win lậu |
| **3** | **Chữ ký số Authenticode** | Kiểm tra chữ ký số trên các file hệ thống cốt lõi: `sppc.dll`, `sppsvc.exe`, `slmgr.vbs`, `slwga.dll` | • Tệp bị mất chữ ký `Microsoft Windows`<br>• File bị chỉnh sửa nhị phân (Binary Patched) |
| **4** | **Đặc trị OHOOK / MAS** *(Công cụ crack phổ biến nhất)* | Quét sự xuất hiện của `C:\Windows\System32\sppcs.dll` và kiểm tra Catalog Signature của `sppc.dll` | • Ohook đổi tên `sppc.dll` gốc thành `sppcs.dll` và chèn DLL giả mạo để bypass kích hoạt |
| **5** | **SppExtComObjHook** | Quét các thư viện DLL Hook trong `System32`, `SysWOW64`, `Windows` | • Dấu vết của KMSpico, KMSAuto Net, AAct Portable |
| **6** | **Registry IFEO Hijacking** | Kiểm tra khóa `Image File Execution Options\SppExtComObj.exe` và `osppsvc.exe` | • Giá trị `Debugger` bị trỏ sang file lạ để chặn tiến trình xác thực bản quyền |
| **7** | **Rogue / Public KMS** | Quét danh sách máy chủ KMS lậu công cộng và Localhost emulator | • Trỏ về `127.0.0.1`, `localhost`<br>• Trỏ về KMS lậu Internet: `kms.msguides.com`, `kms.chinancce.com`... |
| **8** | **Crack Files & Repack Scripts** | Quét thư mục `KMSpico`, `AutoKMS`, `KMSAuto`, `Toolkit` và script `SetupComplete.cmd` | • File cài đặt công cụ crack trên đĩa<br>• Script tự động kích hoạt lậu của các bản Ghost/Repack |
| **9** | **Scheduled Tasks** | Quét các tác vụ lên lịch tự động định kỳ | • Task tự động gia hạn lậu 180 ngày: `\AutoKMS`, `\AutoKMSDaily`, `\KMSpico`, `\KMSAuto` |
| **10** | **Defender Exclusions** | Quét danh sách `ExclusionPath` và `ExclusionProcess` của Windows Defender | • Các thư mục crack được cố tình loại trừ khỏi diệt virus để tránh bị xóa |
| **11** | **Hosts File Tampering** | Quét tệp `C:\Windows\System32\drivers\etc\hosts` | • Chặn hoặc chuyển hướng các domain xác thực của Microsoft (`*.sls.microsoft.com`) |
| **12** | **ĐỐI SOÁT HÓA ĐƠN VAT** | So khớp Serial máy, Hostname, Product Key với Kho hóa đơn qua REST API hoặc File CSV/JSON | • Khớp hóa đơn mua hàng hợp lệ<br>• Cảnh báo lệch phiên bản (mua Home cài Pro)<br>• Cảnh báo lệch Mã số thuế doanh nghiệp |

---

## Cấu Trúc Thư Mục

```
Audit-WindowsLicenseCompliance/
├── photos/                             # Ảnh chụp minh họa thực tế giao diện và báo cáo
│   ├── hero.png                        # Hero banner đại diện dự án
│   ├── image_01.png                    # Giao diện quét pháp y trên PowerShell Console
│   └── image_02.png                    # Mẫu báo cáo HTML đối soát hóa đơn VAT đạt chuẩn
├── Audit-WindowsLicenseCompliance.ps1   # Script kiểm toán chính
├── invoices.json                       # Kho dữ liệu hóa đơn dạng JSON (Dành cho IT/API)
├── invoices.csv                        # Kho dữ liệu hóa đơn dạng CSV (Dành cho Kế toán dùng Excel)
└── README.md                           # Tài liệu hướng dẫn sử dụng & quy chuẩn pháp lý
```

---

## Hướng Dẫn Sử Dụng Chi Tiết

### 1. Kiểm tra Cục bộ trên 1 Thiết bị (Run as Administrator)
Khuyến nghị mở PowerShell với quyền **Run as Administrator** để có thể quét sâu danh sách loại trừ của Windows Defender:

```powershell
# Chạy kiểm tra và xuất báo cáo HTML chuyên nghiệp
powershell.exe -ExecutionPolicy Bypass -File .\Audit-WindowsLicenseCompliance.ps1 -ExportHtml "C:\Audit\BaoCao-$env:COMPUTERNAME.html"
```

![Giao diện thực thi rà soát bản quyền Windows trên PowerShell Console](./photos/image_01.png)  
*Hình 1: Quá trình phân tích pháp y 12 tầng kỹ thuật hiển thị trực quan trên PowerShell Console - bóc tách thông tin thiết bị, OEM Key trong BIOS (MSDM), trạng thái giấy phép SPP, tính toàn vẹn chữ ký số Authenticode và rà soát dấu vết bẻ khóa Ohook/MAS.*

### 2. Kiểm tra kèm Đối soát Hóa đơn Điện tử VAT & Mã số thuế
Doanh nghiệp lưu thông tin hóa đơn mua máy/bản quyền vào file `invoices.json` hoặc `invoices.csv`, sau đó chạy:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Audit-WindowsLicenseCompliance.ps1 `
    -InvoiceFile ".\invoices.json" `
    -ExpectedTaxId "0109876543" `
    -ExportHtml "C:\Audit\BaoCaoTuankhoan-$env:COMPUTERNAME.html"
```

![Báo cáo kiểm toán tuân thủ bản quyền Windows và đối soát hóa đơn VAT](./photos/image_02.png)  
*Hình 2: Mẫu Báo cáo HTML kiểm toán tuân thủ xuất bản tự động - Thể hiện kết quả "Đạt chuẩn tuân thủ 100%", tự động đối soát khớp chính xác số Serial/Service Tag phần cứng máy (`GMNTPH3`) với Hóa đơn điện tử VAT hợp lệ theo Nghị định 341/2025/NĐ-CP phục vụ giải trình thanh tra.*

### 3. Bật Chế độ Bắt buộc phải có Hóa đơn (`-RequireInvoice`)
Nếu bật switch này, những máy sạch crack nhưng chưa tìm thấy hóa đơn đối ứng trong hệ thống sẽ bị gắn cờ `WARNING_MISSING_INVOICE` để nhắc nhở phòng Kế toán bổ sung:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Audit-WindowsLicenseCompliance.ps1 `
    -InvoiceFile ".\invoices.csv" `
    -RequireInvoice `
    -ExportHtml "C:\Audit\Report.html"
```

### 4. Kiểm tra với Máy chủ KMS Nội bộ Doanh nghiệp
Nếu doanh nghiệp có triển khai Volume Activation qua máy chủ KMS nội bộ:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Audit-WindowsLicenseCompliance.ps1 `
    -ExpectedKmsServer "kms.congty.vn" `
    -ExportHtml "C:\Audit\Report.html"
```

---

## Triển Khai Tự Động Hàng Loạt Qua Active Directory GPO

Để quét định kỳ hàng trăm hoặc hàng nghìn máy tính trong mạng doanh nghiệp mà không làm gián đoạn người dùng:

1. **Chuẩn bị Thư mục Mạng Tập trung**:
   - Chia sẻ thư mục `\\FileServer\AuditShare$` và phân quyền:
     - `Domain Computers`: Quyền **Write / Append** (Ghi mới/nối file, không cho đọc báo cáo của máy khác).
     - `IT Admins`: Quyền **Full Control**.
2. **Lưu trữ Script & File Hóa đơn**:
   - Copy `Audit-WindowsLicenseCompliance.ps1` và `invoices.csv` vào `\\FileServer\Netlogon\` hoặc `\\FileServer\AuditShare$`.
3. **Cấu hình Group Policy Object (GPO)**:
   - Mở **Group Policy Management** (`gpmc.msc`).
   - Chọn hoặc tạo GPO: `Audit_Windows_License_Compliance`.
   - Vào: `Computer Configuration` -> `Policies` -> `Windows Settings` -> `Scripts (Startup/Shutdown)` -> `Startup`.
   - Thêm lệnh chạy PowerShell:
     - **Script Name**: `powershell.exe`
     - **Script Parameters**:
       ```powershell
       -ExecutionPolicy Bypass -WindowStyle Hidden -File "\\FileServer\Netlogon\Audit-WindowsLicenseCompliance.ps1" -InvoiceFile "\\FileServer\Netlogon\invoices.csv" -ExpectedTaxId "0109876543" -ExportCsv "\\FileServer\AuditShare$\TongHop_BaoCao_ToanCongTy.csv" -ExportJson "\\FileServer\AuditShare$\Logs\$($env:COMPUTERNAME).json" -Quiet
       ```
4. **Kết quả thu thập**:
   - Toàn bộ máy trạm khi khởi động sẽ tự động ghi kết quả nối tiếp vào file `TongHop_BaoCao_ToanCongTy.csv` và từng file chi tiết `$env:COMPUTERNAME.json`.

---

## Bảng Mã Thoát (Exit Codes) Chuẩn Hóa

| Exit Code | Mã Đánh Giá | Ý Nghĩa Kỹ Thuật & Pháp Lý | Hành Động Cần Thiết |
|:---:|:---|:---|:---|
| **0** | `GENUINE_COMPLIANT` | • Bản quyền hợp lệ, sạch crack.<br>• Đã đối soát thành công Hóa đơn VAT hợp lệ. | Hồ sơ hoàn tất 100%, sẵn sàng xuất trình đoàn thanh tra. |
| **1** | `WARNING_MISSING_INVOICE`<br>/ `SUSPICIOUS_UNVERIFIED` | • Máy sạch kỹ thuật nhưng thiếu hóa đơn đối ứng.<br>• Hoặc dùng Volume License chưa rõ nguồn gốc. | Kế toán bổ sung Hóa đơn điện tử VAT vào hồ sơ lưu trữ. |
| **2** | `NON_COMPLIANT_UNLICENSED` | • Windows chưa kích hoạt hoặc hết hạn dùng thử (Grace Period). | Mua bổ sung bản quyền Windows Pro chính hãng ngay lập tức. |
| **3** | `CRITICAL_PIRATED_CRACKED` | • **PHÁT HIỆN CÔNG CỤ CRACK / OHOOK / KMS LẬU / FILE HỆ THỐNG BỊ VÁ**. | **Xử lý khẩn cấp:** Gỡ crack, chạy `sfc /scannow`, nạp lại OEM key hoặc mua license mới. |

---

## Định Dạng File Hóa Đơn Mẫu

### 1. File JSON (`invoices.json`)
```json
[
  {
    "InvoiceNumber": "0045892",
    "InvoiceSeries": "1C25TNN",
    "InvoiceDate": "2025-04-20",
    "VendorName": "Công ty TNHH MTV Phân phối Synnex FPT",
    "VendorTaxId": "0103608119",
    "BuyerName": "CÔNG TY DOANH NGHIỆP CỦA BẠN",
    "BuyerTaxId": "0109876543",
    "ItemName": "Giấy phép Hệ điều hành Microsoft Windows 11 Pro 64-bit ESD/CSP",
    "LicenseEdition": "Pro",
    "Quantity": 100,
    "TargetIdentifier": "ALL_ENTERPRISE_POOL",
    "Notes": "Gói bản quyền tập trung cho 100 máy toàn công ty"
  },
  {
    "InvoiceNumber": "0012345",
    "InvoiceSeries": "C24TAA",
    "InvoiceDate": "2024-11-15",
    "VendorName": "FPT Shop",
    "VendorTaxId": "0105777650",
    "BuyerName": "CÔNG TY DOANH NGHIỆP CỦA BẠN",
    "BuyerTaxId": "0109876543",
    "ItemName": "Máy tính Dell Vostro 3500 kèm Windows 10 Pro OEM",
    "LicenseEdition": "Pro",
    "Quantity": 1,
    "TargetIdentifier": "GMNTPH3",
    "Notes": "Khớp số Serial phần cứng (Service Tag) in dưới đáy máy"
  }
]
```

### 2. File CSV (`invoices.csv` - Mở và chỉnh sửa bằng Microsoft Excel)
```csv
InvoiceNumber,InvoiceSeries,InvoiceDate,VendorName,VendorTaxId,BuyerName,BuyerTaxId,ItemName,LicenseEdition,Quantity,TargetIdentifier,Notes
0045892,1C25TNN,2025-04-20,Synnex FPT,0103608119,CONG TY BAN,0109876543,Microsoft Windows 11 Pro CSP,Pro,100,ALL_ENTERPRISE_POOL,Goi tap trung 100 may
0012345,C24TAA,2024-11-15,FPT Retail,0105777650,CONG TY BAN,0109876543,Laptop Dell Vostro kem Win 10 Pro OEM,Pro,1,GMNTPH3,Khop Service Tag GMNTPH3
```

> **Ghi chú trường `TargetIdentifier`**:
> - Nhập **Số Serial máy** (ví dụ: `GMNTPH3`) nếu hóa đơn mua kèm máy tính cụ thể.
> - Nhập **Hostname** (ví dụ: `DESKTOP-IT01`) nếu gán cho máy đích danh.
> - Nhập `ALL_ENTERPRISE_POOL` nếu là hóa đơn mua gói bản quyền số lượng lớn dùng chung cho toàn thể doanh nghiệp.

---

## Quy Trình Xử Lý Khi Phát Hiện Máy Bị Crack (Exit Code 3)

Nếu máy tính nhân viên bị phát hiện dùng Win lậu / bẻ khóa, IT cần xử lý triệt để theo các bước:
1. **Xóa bỏ hoàn toàn công cụ crack**:
   - Gỡ bỏ thư mục `C:\Program Files\KMSpico`, `C:\Windows\AutoKMS`, v.v.
   - Xóa các task trong Task Scheduler (`AutoKMS`, `KMSpico`).
   - Xóa file `C:\Windows\System32\sppcs.dll` (nếu dính Ohook).
2. **Khôi phục File Hệ thống Gốc của Microsoft**:
   - Mở CMD/PowerShell với quyền Admin và chạy:
     ```cmd
     sfc /scannow
     dism /online /cleanup-image /restorehealth
     ```
3. **Kích hoạt lại Bản quyền Hợp pháp**:
   - **Trường hợp máy có sẵn OEM Key trong BIOS (MSDM)**:
     Chạy lệnh để nạp lại key gốc theo phần cứng:
     ```cmd
     slmgr.vbs /ipk <OEM_PRODUCT_KEY>
     slmgr.vbs /ato
     ```
   - **Trường hợp không có OEM Key**:
     Cung cấp Product Key chính hãng từ hợp đồng CSP/ESD của doanh nghiệp và kích hoạt bằng `slmgr.vbs /ipk <KEY_MUA_MOI>`.

---

## Tác Giả & Bản Quyền Sử Dụng

- **Tác giả / Nghiên cứu & Phát triển:** [@uzii2208](https://github.com/uzii2208)
- Bộ công cụ được phát triển phục vụ mục đích phòng vệ và quản trị tuân thủ nội bộ doanh nghiệp. Mọi thắc mắc, đóng góp hoặc cần tùy biến thêm module đối soát API ERP/SAP, vui lòng tạo Issue hoặc liên hệ qua GitHub: [@uzii2208](https://github.com/uzii2208).
