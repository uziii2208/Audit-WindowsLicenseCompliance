<#
.SYNOPSIS
    Audit-WindowsLicenseCompliance.ps1 - Enterprise Windows License & Piracy Forensic Audit Tool
    Phần mềm Kiểm tra Bản quyền Windows, Phát hiện Bẻ khóa MAS/HWID/KMS & Đối soát Hóa đơn VAT Doanh nghiệp.
    Phát triển bởi: @uziii2208. Bản quyền MIT License @2026

.DESCRIPTION
    Script chuyên dụng dành cho Quản trị viên IT, Bộ phận Pháp chế, Kế toán & An toàn thông tin Doanh nghiệp
    nhằm rà soát toàn diện tính tuân thủ bản quyền Windows, phục vụ công tác thanh kiểm tra của cơ quan chức năng
    theo Nghị định 341/2025/NĐ-CP (quy định xử phạt vi phạm hành chính trong lĩnh vực sở hữu trí tuệ, quyền tác giả,
    an toàn thông tin mạng và sử dụng phần mềm máy tính), Nghị định 131/2013/NĐ-CP, Nghị định 14/2022/NĐ-CP,
    và Điều 225 Bộ luật Hình sự.

    Các module rà soát pháp y chuyên sâu (14 Tầng phân tích):
    1. Trạng thái bản quyền chính thức qua Software Protection Platform (WMI/CIM/slmgr).
    2. Nhận diện Kênh bản quyền (Retail, OEM:DM, Volume:MAK, Volume:GVLK/KMS) & Bóc tách Default Generic Keys (VK7JG...).
    3. Nhận diện Nền tảng Phần cứng (Máy tính vật lý vs Máy ảo VMware/VirtualBox/Hyper-V) & Rà soát ACPI BIOS MSDM.
    4. Kiểm tra Chữ ký số Authenticode & Tính toàn vẹn của các file hệ thống (sppc.dll, sppsvc.exe, slmgr.vbs).
    5. Phát hiện bẻ khóa Ohook qua sppcs.dll & sppc.dll hook.
    6. ĐIỀU TRA PHÁP Y DẤU VẾT BẺ KHÓA KỸ THUẬT SỐ MAS (HWID, KMS38, TSforge):
       - Quét lịch sử dòng lệnh PowerShell (PSReadLine ConsoleHost_history.txt) tìm lệnh 'irm https://get.activated.win|iex'...
       - Quét nhật ký Event ID 4104 (ScriptBlock Logging) phát hiện mã nguồn MAS/massgrave.
       - Quét bộ nhớ đệm DNS (DNS Client Cache) phát hiện phân giải get.activated.win, massgrave.dev.
       - Quét tệp Prefetch phát hiện gatherosstate.exe (công cụ tạo vé lậu trên Win 10/11) & clipup.exe.
       - Quét thư mục vé bản quyền số C:\ProgramData\Microsoft\Windows\ClipSVC\GenuineTicket & Temp Logs (_Debug.log).
       - Phát hiện bẻ khóa KMS38 kéo dài thời hạn đến năm 2038.
    7. Phát hiện SppExtComObjHook, IFEO Debugger Hijacking cho tiến trình bản quyền.
    8. Nhận diện máy chủ KMS lậu (Localhost emulator 127.0.0.1 hoặc Public Internet KMS servers).
    9. Quét dấu vết các bộ công cụ bẻ khóa: KMSpico, AutoKMS, KMSAuto Net, AAct, Microsoft Toolkit, HEU KMS.
    10. Quét tác vụ đặt lịch tự động re-arm / re-activate (Scheduled Tasks).
    11. Kiểm tra danh sách loại trừ bất thường của Windows Defender (Defender Exclusions).
    12. Kiểm tra can thiệp file HOSTS chuyển hướng máy chủ kích hoạt Microsoft.
    13. ĐỐI SOÁT HÓA ĐƠN ĐIỆN TỬ VAT THỰC TẾ (Chống false positive mẫu template placeholder, thắt chặt điều kiện Enterprise Pool).
    14. Đánh giá rủi ro pháp lý & Xuất báo cáo đa định dạng (Console, HTML chuyên nghiệp, JSON, CSV).

.PARAMETER ExportHtml
    Đường dẫn tệp báo cáo HTML trực quan phục vụ lưu trữ hồ sơ kiểm toán.
    Ví dụ: -ExportHtml "C:\Audit\Report-$($env:COMPUTERNAME).html"

.PARAMETER ExportJson
    Đường dẫn tệp JSON phục vụ đẩy dữ liệu về SIEM / Log Central / Splunk / Elastic.

.PARAMETER ExportCsv
    Đường dẫn tệp CSV phục vụ tổng hợp hàng loạt máy tính qua GPO / Intune.

.PARAMETER ExpectedKmsServer
    FQDN hoặc IP của máy chủ KMS nội bộ hợp pháp của công ty (nếu có sử dụng Volume Activation).

.PARAMETER InvoiceFile
    Đường dẫn file danh mục hóa đơn bản quyền doanh nghiệp (.json, .csv hoặc .xml hóa đơn điện tử).
    Nếu không truyền, script tự động dò tìm: .\invoices.json, .\invoices.csv.

.PARAMETER InvoiceApiUrl
    URL của API / SAM Portal nội bộ công ty để fetch dữ liệu hóa đơn đối ứng từ xa.
    Ví dụ: -InvoiceApiUrl "https://sam.congty.vn/api/invoices"

.PARAMETER ExpectedTaxId
    Mã số thuế doanh nghiệp của bạn (dùng để xác thực bên mua trên hóa đơn điện tử VAT).

.PARAMETER RequireInvoice
    Bật switch này nếu bắt buộc máy phải có hóa đơn VAT đối ứng mới đạt chuẩn COMPLIANT.

.PARAMETER Quiet
    Chế độ chạy ngầm không hiển thị giao diện console (thích hợp chạy qua GPO/SCCM/RMM).

.OUTPUTS
    Exit Codes:
    0 = COMPLIANT (Bản quyền hợp lệ, sạch crack, đối soát hóa đơn VAT thành công)
    1 = SUSPICIOUS / WARNING (Cần bổ sung/xác minh hóa đơn VAT hoặc hợp đồng Volume Licensing)
    2 = NON-COMPLIANT (Chưa kích hoạt hoặc đã hết hạn dùng thử)
    3 = CRITICAL_PIRATED (Phát hiện dấu vết bẻ khóa MAS, HWID, KMS lậu, file hệ thống bị vá)
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ExportHtml = "",

    [Parameter(Mandatory = $false)]
    [string]$ExportJson = "",

    [Parameter(Mandatory = $false)]
    [string]$ExportCsv = "",

    [Parameter(Mandatory = $false)]
    [string]$ExpectedKmsServer = "",

    [Parameter(Mandatory = $false)]
    [string]$InvoiceFile = "",

    [Parameter(Mandatory = $false)]
    [string]$InvoiceApiUrl = "",

    [Parameter(Mandatory = $false)]
    [string]$ExpectedTaxId = "",

    [Parameter(Mandatory = $false)]
    [switch]$RequireInvoice,

    [Parameter(Mandatory = $false)]
    [switch]$Quiet
)

$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ==============================================================================
# 0. KHỞI TẠO BIẾN TOÀN CỤC & HÀM TIỆN ÍCH
# ==============================================================================
$StartTime = Get-Date
$AuditFindings = [System.Collections.Generic.List[PSObject]]::new()
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Add-Finding {
    param (
        [string]$Category,
        [string]$Item,
        [ValidateSet("PASSED", "SUSPICIOUS", "WARNING", "FAILED")]
        [string]$Status,
        [string]$Details,
        [string]$LegalRisk
    )
    $finding = [PSCustomObject]@{
        Category  = $Category
        Item      = $Item
        Status    = $Status
        Details   = $Details
        LegalRisk = $LegalRisk
    }
    $AuditFindings.Add($finding)
}

function Write-Section {
    param ([string]$Title)
    if (-not $Quiet) {
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "  $Title" -ForegroundColor White
        Write-Host ("=" * 80) -ForegroundColor Cyan
    }
}

function Write-ResultItem {
    param (
        [string]$Label,
        [string]$Value,
        [string]$Status = "INFO"
    )
    if ($Quiet) { return }
    $color = "White"
    switch ($Status) {
        "PASSED"     { $color = "Green" }
        "SUSPICIOUS" { $color = "Yellow" }
        "WARNING"    { $color = "Magenta" }
        "FAILED"     { $color = "Red" }
        "INFO"       { $color = "Cyan" }
    }
    Write-Host ("  [{0,-10}] {1,-35}: {2}" -f $Status, $Label, $Value) -ForegroundColor $color
}

# Danh mục Product Key mặc định của Microsoft (Default Generic Product Keys)
$KnownGenericProductKeys = @{
    "3V66T" = [PSCustomObject]@{ Edition = "Windows 10/11 Pro"; FullKey = "VK7JG-NPHTM-C97JM-9MPGT-3V66T"; Type = "Generic Retail / Digital License" }
    "8HVX7" = [PSCustomObject]@{ Edition = "Windows 10/11 Home"; FullKey = "YTMG3-N6DKC-DKB77-7M9GH-8HVX7"; Type = "Generic Retail / Digital License" }
    "6F4BT" = [PSCustomObject]@{ Edition = "Windows 10/11 Home Single Language"; FullKey = "BT79Q-G7N6G-PGBYW-4YWX6-6F4BT"; Type = "Generic Retail / Digital License" }
    "WT2RQ" = [PSCustomObject]@{ Edition = "Windows 10/11 Home Single Language"; FullKey = "WYPNQ-8C467-V2W6J-TX4WX-WT2RQ"; Type = "Generic Retail / Digital License" }
    "RR888" = [PSCustomObject]@{ Edition = "Windows 10/11 Pro Education"; FullKey = "6TP4R-GNPTD-KYYHQ-2337H-RR888"; Type = "Generic Retail / Digital License" }
    "2YV77" = [PSCustomObject]@{ Edition = "Windows 10/11 Pro for Workstations"; FullKey = "DXG7C-N36C4-C4HTG-X4T3X-2YV77"; Type = "Generic Retail / Digital License" }
    "8HV2C" = [PSCustomObject]@{ Edition = "Windows 10/11 Enterprise"; FullKey = "XGVPP-NMH47-7TTHJ-W3FW7-8HV2C"; Type = "Generic Retail / Digital License" }
    "7CFBY" = [PSCustomObject]@{ Edition = "Windows 10/11 Education"; FullKey = "YNMGQ-8RYV3-4PGQ3-C8XTP-7CFBY"; Type = "Generic Retail / Digital License" }
    "J462D" = [PSCustomObject]@{ Edition = "Windows 10/11 Enterprise LTSC 2019/2021"; FullKey = "M7XTQ-FN8P6-TTKYV-9D4CC-J462D"; Type = "Generic Retail / Digital License" }
    "BHDCD" = [PSCustomObject]@{ Edition = "Windows 10/11 IoT Enterprise LTSC"; FullKey = "K9VKN-3BGWV-Y624W-MCRMQ-BHDCD"; Type = "Generic Retail / Digital License" }
    "CCC78" = [PSCustomObject]@{ Edition = "Windows 11 Pro SE"; FullKey = "43TBQ-NH92J-XKXXK-373CT-CCC78"; Type = "Generic Retail / Digital License" }
    "MDWWW" = [PSCustomObject]@{ Edition = "Windows 10 Enterprise LTSB 2015"; FullKey = "FWN7H-PF93Q-4GGP8-M8RF3-MDWWW"; Type = "Generic Retail / Digital License" }
    "4488K" = [PSCustomObject]@{ Edition = "Windows 10 Enterprise LTSB 2016"; FullKey = "2NBWW-MBBJ9-G4K4K-VD427-4488K"; Type = "Generic Retail / Digital License" }
    "T83GX" = [PSCustomObject]@{ Edition = "Windows 10/11 Pro KMS Client"; FullKey = "W269N-WFGWX-YVC9B-4J6C9-T83GX"; Type = "Generic Volume GVLK" }
}

# ==============================================================================
# 1. THÔNG TIN THIẾT BỊ, PHẦN CỨNG & NỀN TẢNG ẢO HÓA
# ==============================================================================
Write-Section "1. THÔNG TIN THIẾT BỊ & HỆ ĐIỀU HÀNH"

$ComputerName = $env:COMPUTERNAME
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$CompSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$BiosInfo = Get-CimInstance -ClassName Win32_BIOS
$CsProduct = Get-CimInstance -ClassName Win32_ComputerSystemProduct

$OSCaption      = $OSInfo.Caption
$OSVersion      = $OSInfo.Version
$OSBuild        = $OSInfo.BuildNumber
$OSArch         = $OSInfo.OSArchitecture
$InstallDate    = $OSInfo.InstallDate
$Manufacturer   = if ($CompSystem.Manufacturer) { $CompSystem.Manufacturer.Trim() } else { "Unknown" }
$Model          = if ($CompSystem.Model) { $CompSystem.Model.Trim() } else { "Unknown" }
$DomainJoined   = $CompSystem.PartOfDomain
$DomainName     = $CompSystem.Domain
$HardwareSerial = if ($BiosInfo.SerialNumber) { $BiosInfo.SerialNumber.Trim() } else { "Unknown" }
$HardwareUUID   = if ($CsProduct.UUID) { $CsProduct.UUID.Trim() } else { "Unknown" }

# Nhận diện phần cứng vật lý vs Máy ảo (Virtual Machine)
$IsVirtualMachine = $false
$VmPlatform = ""
$VmKeywords = @("VMware", "VirtualBox", "Virtual Machine", "Hyper-V", "QEMU", "KVM", "Xen", "Parallels", "Standard PC")

foreach ($kw in $VmKeywords) {
    if ($Manufacturer -like "*$kw*" -or $Model -like "*$kw*" -or $HardwareSerial -like "*$kw*") {
        $IsVirtualMachine = $true
        $VmPlatform = $kw
        break
    }
}
if ($CompSystem.Model -match "Virtual" -or $BiosInfo.SerialNumber -like "*VMware*" -or $BiosInfo.SerialNumber -like "*VirtualBox*") {
    $IsVirtualMachine = $true
    if (-not $VmPlatform) { $VmPlatform = "Virtual Machine" }
}

Write-ResultItem "Tên máy tính (Hostname)" $ComputerName "INFO"
Write-ResultItem "Số Serial phần cứng (Service Tag)" $HardwareSerial "INFO"
Write-ResultItem "Người dùng hiện tại" $CurrentUser "INFO"
Write-ResultItem "Nhà sản xuất / Model" "$Manufacturer $Model" "INFO"
Write-ResultItem "Loại phần cứng" $(if ($IsVirtualMachine) { "Máy ảo ($VmPlatform) [Không có OEM BIOS]" } else { "Máy tính vật lý (Physical Host)" }) "INFO"
Write-ResultItem "Phiên bản Windows" "$OSCaption (Build $OSBuild, $OSArch)" "INFO"
Write-ResultItem "Gia nhập Domain (AD)" $(if ($DomainJoined) { "Có ($DomainName)" } else { "Không (Workgroup)" }) "INFO"
Write-ResultItem "Quyền thực thi Script" $(if ($IsAdmin) { "Administrator (Toàn quyền rà soát)" } else { "Standard User (Khuyến nghị chạy Run as Admin để quét sâu Defender & Nhật ký)" }) $(if ($IsAdmin) { "PASSED" } else { "SUSPICIOUS" })

# Kiểm tra OEM Factory License trong BIOS/UEFI (ACPI MSDM table)
$Oa3Key = ""
try {
    $sppService = Get-CimInstance -ClassName SoftwareLicensingService
    if ($sppService.OA3xOriginalProductKey) {
        $Oa3Key = $sppService.OA3xOriginalProductKey.Trim()
    }
} catch {}

if ($Oa3Key) {
    Write-ResultItem "OEM Key trong BIOS (MSDM)" "$Oa3Key (Bản quyền gốc đi theo phần cứng máy)" "PASSED"
    Add-Finding "Hardware License" "BIOS MSDM Key" "PASSED" "Máy tính có sẵn key bản quyền OEM nhúng trong bo mạch chủ từ nhà sản xuất ($Oa3Key)." "Hợp lệ về phần cứng"
} else {
    $oemMsg = if ($IsVirtualMachine) { "Không có (Máy ảo không hỗ trợ nạp key OEM vào BIOS)" } else { "Không phát hiện (Máy lắp ráp, máy cài đặt lại hoặc mainboard không có key OEM)" }
    Write-ResultItem "OEM Key trong BIOS (MSDM)" $oemMsg "INFO"
    Add-Finding "Hardware License" "BIOS MSDM Key" "INFO" "Không có key OEM trong BIOS. Bắt buộc phải có Giấy phép Retail/FPP hoặc Volume Licensing doanh nghiệp kèm hóa đơn VAT." "Cần chứng từ kèm theo"
}

if ($IsVirtualMachine) {
    Add-Finding "Hardware Platform" "Môi trường Máy Ảo" "INFO" "Thiết bị là máy ảo ($VmPlatform). Máy ảo không thể sở hữu bản quyền OEM phần cứng. Doanh nghiệp bắt buộc phải có Giấy phép Volume (KMS/MAK) từ máy chủ nội bộ hoặc hóa đơn bản quyền riêng biệt." "Cần chứng từ cấp phép riêng cho máy ảo"
}

# ==============================================================================
# 2. KIỂM TRA TRẠNG THÁI GIẤY PHÉP PHẦN MỀM CHÍNH THỨC (SPP WMI)
# ==============================================================================
Write-Section "2. PHÂN TÍCH GIẤY PHÉP MICROSOFT SOFTWARE PROTECTION PLATFORM (SPP)"

$WinProduct = $null
try {
    $products = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "PartialProductKey is not null"
    foreach ($p in $products) {
        if ($p.Name -like "*Windows*" -and $p.Description -like "*Windows*") {
            $WinProduct = $p
            break
        }
    }
} catch {}

$LicenseStatusString = "Unknown"
$LicenseStatusCode = -1
$ProductKeyChannel = "Unknown"
$PartialKey = "None"
$ProductDescription = "None"
$KmsMachineConfigured = ""
$KmsMachineDiscovered = ""
$GracePeriodDays = 0

if ($WinProduct) {
    $LicenseStatusCode = $WinProduct.LicenseStatus
    $PartialKey = if ($WinProduct.PartialProductKey) { $WinProduct.PartialProductKey.Trim().ToUpper() } else { "None" }
    $ProductDescription = $WinProduct.Description
    $ProductKeyChannel = $WinProduct.ProductKeyChannel
    $KmsMachineConfigured = $WinProduct.KeyManagementServiceMachine
    $KmsMachineDiscovered = $WinProduct.DiscoveredKeyManagementServiceMachineName
    if ($WinProduct.GracePeriodRemaining) {
        $GracePeriodDays = [math]::Round($WinProduct.GracePeriodRemaining / 1440, 1)
    }

    switch ($LicenseStatusCode) {
        0 { $LicenseStatusString = "Unlicensed (Chưa có giấy phép)" }
        1 { $LicenseStatusString = "Licensed (Đã kích hoạt)" }
        2 { $LicenseStatusString = "OOBGrace (Đang trong thời gian dùng thử ban đầu)" }
        3 { $LicenseStatusString = "OOTGrace (Hết hạn thời gian gia hạn)" }
        4 { $LicenseStatusString = "NonGenuineGrace (Microsoft phát hiện không chính hãng)" }
        5 { $LicenseStatusString = "Notification (Chế độ cảnh báo bản quyền)" }
        6 { $LicenseStatusString = "ExtendedGrace (Gia hạn mở rộng)" }
        default { $LicenseStatusString = "Mã trạng thái lạ ($LicenseStatusCode)" }
    }
}

# Kiểm tra qua slmgr.vbs /xpr để xác định vĩnh viễn hay có thời hạn
$SlmgrXprOutput = ""
$IsPermanentActivation = $false
try {
    $SlmgrProcess = Start-Process -FilePath "cscript.exe" -ArgumentList "//nologo `"$env:windir\System32\slmgr.vbs`" /xpr" -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$env:TEMP\slmgr_xpr.txt"
    if (Test-Path "$env:TEMP\slmgr_xpr.txt") {
        $SlmgrXprOutput = (Get-Content "$env:TEMP\slmgr_xpr.txt" -Raw).Trim()
        Remove-Item "$env:TEMP\slmgr_xpr.txt" -Force -ErrorAction SilentlyContinue
    }
} catch {}

if ($SlmgrXprOutput -match "permanently activated|kích hoạt vĩnh viễn") {
    $IsPermanentActivation = $true
}

# Nhận diện Default Generic Product Key
$IsGenericKey = $false
$GenericKeyMatch = $null
if ($PartialKey -ne "None" -and $KnownGenericProductKeys.ContainsKey($PartialKey)) {
    $IsGenericKey = $true
    $GenericKeyMatch = $KnownGenericProductKeys[$PartialKey]
}

# Kiểm tra dấu vết bẻ khóa KMS38 (Thời hạn kéo dài tới năm 2038)
$IsKms38Crack = ($SlmgrXprOutput -match "2038" -or ($WinProduct -and $WinProduct.GracePeriodRemaining -gt 5000000))

Write-ResultItem "Trạng thái Giấy phép" $LicenseStatusString $(if ($LicenseStatusCode -eq 1 -and -not $IsKms38Crack) { "PASSED" } else { "FAILED" })
Write-ResultItem "Kênh cấp phép (Channel)" $ProductKeyChannel $(if ($ProductKeyChannel -match "Retail|OEM") { "PASSED" } else { "SUSPICIOUS" })
Write-ResultItem "5 ký tự cuối Product Key" "$PartialKey $(if ($IsGenericKey) { '[Default Generic Key / Digital License]' } else { '' })" $(if ($IsGenericKey -and $IsVirtualMachine) { "FAILED" } elseif ($IsGenericKey -and -not $Oa3Key) { "WARNING" } else { "INFO" })
Write-ResultItem "Mô tả sản phẩm" $ProductDescription "INFO"
Write-ResultItem "Thời hạn kích hoạt (slmgr /xpr)" $(if ($SlmgrXprOutput) { $SlmgrXprOutput.Replace("`r`n", " - ") } else { "Không truy xuất được" }) $(if ($IsKms38Crack) { "FAILED" } elseif ($IsPermanentActivation) { "PASSED" } else { "SUSPICIOUS" })

if ($IsKms38Crack) {
    Add-Finding "SPP Licensing" "KMS38 Bẻ khóa" "FAILED" "Phát hiện thời hạn bản quyền kết thúc vào năm 2038 ($SlmgrXprOutput). Đây là chữ ký bẻ khóa đặc trưng của công cụ MAS KMS38 (lợi dụng vé ClipSVC gia hạn tới 2038)." "Bẻ khóa bản quyền có chủ đích theo NĐ 341/2025/NĐ-CP"
} elseif ($LicenseStatusCode -eq 1) {
    if ($IsGenericKey -and $IsVirtualMachine) {
        Write-ResultItem "Đánh giá Product Key" "Generic Key ($PartialKey) trên Máy Ảo! Dấu hiệu bẻ khóa kỹ thuật số MAS HWID" "FAILED"
        Add-Finding "SPP Licensing" "Generic Key trên Máy Ảo" "FAILED" "Máy ảo ($VmPlatform) được kích hoạt vĩnh viễn bằng Default Generic Key ($PartialKey). Máy ảo không thể sở hữu bản quyền OEM phần cứng. Đây là dấu hiệu đặc trưng 100% của công cụ bẻ khóa kỹ thuật số MAS HWID (Microsoft Activation Scripts)." "Kích hoạt lậu bằng MAS HWID trên máy ảo"
    } elseif ($IsGenericKey -and -not $Oa3Key) {
        Write-ResultItem "Đánh giá Product Key" "Generic Key ($PartialKey) không có OEM BIOS. Cần Hóa đơn VAT / Tài khoản MSA" "WARNING"
        Add-Finding "SPP Licensing" "Generic Key không OEM" "WARNING" "Windows sử dụng Default Generic Key ($PartialKey) nhưng bo mạch chủ không có key OEM gốc. Cần chứng từ Hóa đơn điện tử VAT hoặc tài khoản Microsoft Account (MSA) để chứng minh tính hợp pháp." "Nghi vấn bẻ khóa kỹ thuật số MAS HWID"
    } elseif ($ProductKeyChannel -match "OEM") {
        Add-Finding "License Channel" "Kênh OEM" "PASSED" "Windows kích hoạt theo bản quyền OEM kèm máy tính." "Tuân thủ hợp pháp nếu mua kèm máy"
    } elseif ($ProductKeyChannel -match "Retail") {
        Add-Finding "License Channel" "Kênh Retail" $(if ($IsGenericKey) { "WARNING" } else { "PASSED" }) "Windows kích hoạt theo bản quyền bán lẻ Retail/FPP." "Hợp pháp nếu có hóa đơn/license hợp lệ"
    } elseif ($ProductKeyChannel -match "Volume:MAK") {
        Add-Finding "License Channel" "Kênh Volume:MAK" "PASSED" "Windows kích hoạt qua mã số lượng lớn MAK." "Cần hợp đồng Volume Licensing với Microsoft"
    } elseif ($ProductKeyChannel -match "Volume:GVLK") {
        Add-Finding "License Channel" "Kênh Volume:GVLK (KMS)" "SUSPICIOUS" "Windows đang sử dụng khóa máy trạm KMS (GVLK). Cần đối soát máy chủ KMS có phải nội bộ doanh nghiệp hay không." "Rủi ro cao nếu dùng KMS lậu"
    }
} else {
    Add-Finding "License Status" "Chưa kích hoạt" "FAILED" "Trạng thái bản quyền: $LicenseStatusString. Máy vi phạm quy định bản quyền phần mềm." "Xử phạt vi phạm bản quyền theo NĐ 341/2025/NĐ-CP"
}

# ==============================================================================
# 3. KIỂM TRA MÁY CHỦ KMS & PHÁT HIỆN MÁY CHỦ LẬU
# ==============================================================================
Write-Section "3. RÀ SOÁT NGUỒN GỐC MÁY CHỦ KÍCH HOẠT KMS"

$KnownRogueKmsHosts = @(
    "127.0.0.1", "localhost", "0.0.0.0", "::1",
    "kms.msguides.com", "kms8.msguides.com", "kms9.msguides.com",
    "kms.digiboy.ir", "kms.03k.org", "kms.chinancce.com", "kms.lotro.cc",
    "kms.cangshui.net", "kms.library.hk", "kms.teevee.asia", "kms.zhuxiaokai.biz",
    "kms.srv.crabdance.com", "kms.ddns.net", "kms.shuax.com", "kms.luody.info",
    "kms.xspace.in", "kms.catqu.com", "kms.vfree.org", "kms.cxzy.vip",
    "kms.mindfly.cn", "kms.landiannews.com", "kms.ghpym.com",
    "kms.senbe.cn", "kms.cz9.cn", "kms.moeclub.org", "kms.bige0.com", "kms.loli.best"
)

$KmsServer = if ($KmsMachineConfigured) { $KmsMachineConfigured } else { $KmsMachineDiscovered }

if ($ProductKeyChannel -match "Volume:GVLK" -or $KmsServer) {
    Write-ResultItem "Máy chủ KMS cấu hình" $(if ($KmsMachineConfigured) { $KmsMachineConfigured } else { "Chưa đặt cố định (Tự dò DNS SRV)" }) "INFO"
    Write-ResultItem "Máy chủ KMS tự dò được" $(if ($KmsMachineDiscovered) { $KmsMachineDiscovered } else { "Không có" }) "INFO"

    $IsRogueKms = $false
    $RogueReason = ""

    foreach ($rogue in $KnownRogueKmsHosts) {
        if ($KmsServer -like "*$rogue*") {
            $IsRogueKms = $true
            $RogueReason = "Trỏ vào máy chủ KMS lậu / giả lập: $rogue"
            break
        }
    }

    if ($IsRogueKms) {
        Write-ResultItem "Đánh giá máy chủ KMS" "PHÁT HIỆN MÁY CHỦ CRACK/LẬU ($RogueReason)" "FAILED"
        Add-Finding "KMS Server" "Máy chủ KMS lậu" "FAILED" "Hệ thống trỏ đến máy chủ KMS bẻ khóa: $KmsServer. Đây là hành vi vi phạm bản quyền có chủ đích." "Xử phạt mức nghiêm trọng nhất theo NĐ 341/2025/NĐ-CP"
    } elseif ($ExpectedKmsServer -and $KmsServer -notlike "*$ExpectedKmsServer*") {
        Write-ResultItem "Đánh giá máy chủ KMS" "Không khớp với máy chủ KMS doanh nghiệp ($ExpectedKmsServer)" "WARNING"
        Add-Finding "KMS Server" "KMS ngoài doanh nghiệp" "WARNING" "Máy chủ KMS ($KmsServer) không thuộc máy chủ nội bộ đã phê duyệt ($ExpectedKmsServer)." "Cần làm rõ nguồn gốc"
    } elseif ($KmsServer -and -not $DomainJoined) {
        Write-ResultItem "Đánh giá máy chủ KMS" "Máy tính không thuộc Domain nhưng lại dùng Volume KMS ($KmsServer)" "SUSPICIOUS"
        Add-Finding "KMS Server" "KMS không có AD Domain" "SUSPICIOUS" "Máy tính cá nhân/workgroup không gia nhập domain công ty nhưng kích hoạt qua KMS." "Khả năng cao do thợ cài dạo bẻ khóa"
    } else {
        Write-ResultItem "Đánh giá máy chủ KMS" $(if ($KmsServer) { "Máy chủ hợp lệ: $KmsServer" } else { "Không có máy chủ KMS lạ" }) "PASSED"
        Add-Finding "KMS Server" "Máy chủ KMS" "PASSED" "Không phát hiện địa chỉ KMS độc hại hoặc giả lập." "Bình thường"
    }
} else {
    Write-ResultItem "Máy chủ KMS" "Không sử dụng (Kênh Retail / OEM)" "PASSED"
    Add-Finding "KMS Server" "KMS không áp dụng" "PASSED" "Máy không sử dụng cơ chế kích hoạt KMS." "Hợp lệ"
}

# Kiểm tra lắng nghe cổng mạng KMS (TCP 1688) cục bộ trên máy trạm
$KmsPortListening = $false
$KmsPortProcInfo = ""
try {
    $tcpConns = Get-NetTCPConnection -LocalPort 1688 -State Listen -ErrorAction SilentlyContinue
    if ($tcpConns) {
        $KmsPortListening = $true
        $pids = ($tcpConns | Select-Object -ExpandProperty OwningProcess -Unique)
        $procNames = @()
        foreach ($p in $pids) {
            try {
                $pr = Get-Process -Id $p -ErrorAction SilentlyContinue
                if ($pr) { $procNames += "$($pr.Name) (PID: $p, Path: $($pr.Path))" }
            } catch {}
        }
        $KmsPortProcInfo = $procNames -join "; "
    }
} catch {}

if ($KmsPortListening) {
    Write-ResultItem "Cổng KMS nội bộ (TCP 1688)" "PHÁT HIỆN PORT 1688 ĐANG MỞ: $KmsPortProcInfo" "FAILED"
    Add-Finding "KMS Server" "KMS Port 1688 Listener" "FAILED" "Máy trạm đang mở cổng lắng nghe TCP 1688 ($KmsPortProcInfo). Đây là đặc trưng của trình giả lập KMS nội bộ (vlmcsd, KMSpico, KMSAuto, py-kms, HEU KMS) đang chạy ngầm để bẻ khóa." "Giả lập máy chủ bản quyền trên máy khách theo NĐ 341/2025/NĐ-CP"
} else {
    Write-ResultItem "Cổng KMS nội bộ (TCP 1688)" "Sạch (Máy trạm không mở dịch vụ KMS giả lập)" "PASSED"
    Add-Finding "KMS Server" "KMS Port 1688 Listener" "PASSED" "Cổng TCP 1688 không mở." "Bình thường"
}

# ==============================================================================
# 4. KIỂM TRA CHỮ KÝ SỐ FILE HỆ THỐNG & KỸ THUẬT BẺ KHÓA OHOOK
# ==============================================================================
Write-Section "4. KIỂM TRA CHỮ KÝ SỐ FILE HỆ THỐNG & KỸ THUẬT BẺ KHÓA OHOOK"

$CriticalLicensingFiles = @(
    "$env:windir\System32\sppc.dll",
    "$env:windir\System32\sppsvc.exe",
    "$env:windir\System32\slmgr.vbs",
    "$env:windir\System32\slwga.dll",
    "$env:windir\System32\sppcommdlg.dll"
)

$IntegrityFailed = $false
foreach ($filePath in $CriticalLicensingFiles) {
    if (Test-Path $filePath) {
        $sig = Get-AuthenticodeSignature -FilePath $filePath
        $fileName = [System.IO.Path]::GetFileName($filePath)
        $isMicrosoftSigned = ($sig.SignerCertificate.Subject -like "*Microsoft Windows*" -or $sig.SignerCertificate.Subject -like "*Microsoft Corporation*")

        if ($sig.Status -eq "Valid" -and $isMicrosoftSigned) {
            Write-ResultItem "Chữ ký: $fileName" "Hợp lệ (Microsoft Windows Signed)" "PASSED"
            Add-Finding "File Integrity" $fileName "PASSED" "Tệp $fileName có chữ ký số hợp lệ của Microsoft Corporation." "Nguyên bản"
        } else {
            $IntegrityFailed = $true
            Write-ResultItem "Chữ ký: $fileName" "KHÔNG HỢP LỆ! (Trạng thái: $($sig.Status), Ký bởi: $($sig.SignerCertificate.Subject))" "FAILED"
            Add-Finding "File Integrity" $fileName "FAILED" "Tệp cốt lõi $fileName bị sửa đổi nhị phân, mất chữ ký số gốc hoặc bị thay thế bởi công cụ bẻ khóa." "Dấu hiệu can thiệp mã nguồn hệ điều hành trái phép"
        }
    }
}

$OhookDetected = $false
$SppcsPath = "$env:windir\System32\sppcs.dll"
$SppcSys32 = "$env:windir\System32\sppc.dll"

if (Test-Path $SppcsPath) {
    $OhookDetected = $true
    Write-ResultItem "Phát hiện OHOOK HackTool" "TÌM THẤY TỆP TỒN TẠI: $SppcsPath" "FAILED"
    Add-Finding "Ohook Mas Detection" "Tệp sppcs.dll" "FAILED" "Phát hiện tệp sppcs.dll trong System32. Đây là chữ ký 100% của công cụ bẻ khóa Ohook (Microsoft Activation Scripts)." "Hành vi bẻ khóa bản quyền có chủ đích"
}

if (Test-Path $SppcSys32) {
    $sppcSig = Get-AuthenticodeSignature $SppcSys32
    if ($sppcSig.Status -ne "Valid") {
        $OhookDetected = $true
        Write-ResultItem "Kiểm tra sppc.dll Hook" "sppc.dll bị vô hiệu hóa chữ ký hoặc bị vá nhị phân!" "FAILED"
        Add-Finding "Ohook Mas Detection" "Vá nhị phân sppc.dll" "FAILED" "sppc.dll không có chữ ký hợp lệ. Khả năng cao đã bị tiêm mã giả lập giấy phép Ohook." "Vi phạm sở hữu trí tuệ nghiêm trọng"
    }
}

if (-not $OhookDetected) {
    Write-ResultItem "Kiểm tra OHOOK / MAS" "Không phát hiện dấu vết bẻ khóa Ohook (sppc.dll/sppcs.dll sạch)" "PASSED"
    Add-Finding "Ohook Mas Detection" "Ohook Artifacts" "PASSED" "Không phát hiện tệp hoặc cơ chế can thiệp Ohook." "Bình thường"
}

# ==============================================================================
# 5. ĐIỀU TRA PHÁP Y DẤU VẾT BẺ KHÓA MAS & POWERSHELL (HWID, DNS, PREFETCH)
# ==============================================================================
Write-Section "5. ĐIỀU TRA DẤU VẾT BẺ KHÓA KỸ THUẬT SỐ MAS (HWID, POWERSHELL & PREFETCH)"

$MasTraceFound = $false

# 5.1. Quét Lịch sử dòng lệnh PowerShell (PSReadLine ConsoleHost_history.txt)
$PsHistoryFiles = [System.Collections.Generic.List[string]]::new()
$defaultPsHist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $defaultPsHist) { $PsHistoryFiles.Add($defaultPsHist) }

$UserProfiles = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue
foreach ($up in $UserProfiles) {
    $uHist = "$($up.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if ((Test-Path $uHist) -and (-not $PsHistoryFiles.Contains($uHist))) {
        $PsHistoryFiles.Add($uHist)
    }
}

$MasPsCommands = [System.Collections.Generic.List[string]]::new()
$MasPattern = 'get\.activated\.win|massgrave|massgravel|git\.activated\.win|HWID_Activation|MAS_AIO|TSforge|clipup\s+-v\s+-o|gatherosstate|sppcs\.dll|slmgr.*ipk.*VK7JG|irm.*activated\.win|irm.*massgrave'

foreach ($hf in $PsHistoryFiles) {
    try {
        $foundMatches = Select-String -Path $hf -Pattern $MasPattern -ErrorAction SilentlyContinue
        foreach ($m in $foundMatches) {
            $MasPsCommands.Add($m.Line.Trim())
        }
    } catch {}
}

if ($MasPsCommands.Count -gt 0) {
    $MasTraceFound = $true
    $sampleCmd = $MasPsCommands[0]
    if ($sampleCmd.Length -gt 55) { $sampleCmd = $sampleCmd.Substring(0, 52) + "..." }
    Write-ResultItem "Lịch sử PowerShell (PSReadLine)" "PHÁT HIỆN LỆNH BẺ KHÓA: $sampleCmd" "FAILED"
    Add-Finding "MAS Forensics" "PowerShell History" "FAILED" "Tìm thấy lệnh tải/thực thi công cụ bẻ khóa MAS trong lịch sử PowerShell: '$($MasPsCommands[0])'. Đây là chứng cứ người dùng đã trực tiếp chạy lệnh crack." "Bằng chứng pháp lý trực tiếp về hành vi vi phạm"
} else {
    Write-ResultItem "Lịch sử PowerShell (PSReadLine)" "Sạch (Không có lệnh irm/iex gọi get.activated.win/massgrave)" "PASSED"
    Add-Finding "MAS Forensics" "PowerShell History" "PASSED" "Lịch sử PowerShell không chứa lệnh bẻ khóa MAS." "Bình thường"
}

# 5.2. Quét Nhật ký ScriptBlock Logging (Event ID 4104)
$PsEventFound = $false
try {
    $filterScriptBlock = @{
        LogName   = 'Microsoft-Windows-PowerShell/Operational'
        Id        = 4104
        StartTime = (Get-Date).AddDays(-180)
    }
    $events = Get-WinEvent -FilterHashtable $filterScriptBlock -MaxEvents 150 -ErrorAction SilentlyContinue
    foreach ($evt in $events) {
        $msg = $evt.Message
        if ($msg -match 'get\.activated\.win|massgrave\.dev|activated\.win|git\.activated\.win|HWID_Activation|GenuineTicket\.xml|MAS_AIO|clipup\s+-v\s+-o|TSforge') {
            $PsEventFound = $true
            break
        }
    }
} catch {}

if ($PsEventFound) {
    $MasTraceFound = $true
    Write-ResultItem "Nhật ký PowerShell Event 4104" "PHÁT HIỆN SCRIPTBLOCK CHỨA MÃ NGUỒN BẺ KHÓA MAS!" "FAILED"
    Add-Finding "MAS Forensics" "Event Log 4104" "FAILED" "Nhật ký PowerShell ScriptBlock ghi nhận sự hiện diện của mã nguồn bẻ khóa MAS (get.activated.win/massgrave)." "Chứng cứ thực thi mã độc hại can thiệp bản quyền"
} else {
    Write-ResultItem "Nhật ký PowerShell Event 4104" "Không phát hiện mã crack MAS trong nhật ký hệ thống" "PASSED"
    Add-Finding "MAS Forensics" "Event Log 4104" "PASSED" "Không có Event 4104 liên quan đến MAS." "Bình thường"
}

# 5.3. Quét Bộ nhớ đệm DNS (DNS Client Cache)
$DnsCrackFound = $false
$DnsEntriesMatched = @()
$DnsPattern = "get\.activated\.win|massgrave\.dev|activated\.win|git\.activated\.win|idkey\.massgrave\.dev|msguides\.com"
try {
    $dnsEntries = Get-DnsClientCache -ErrorAction SilentlyContinue
    foreach ($entry in $dnsEntries) {
        $eName = $entry.Entry
        $eData = $entry.Data
        if ($eName -match $DnsPattern -or $eData -match $DnsPattern) {
            $DnsCrackFound = $true
            $DnsEntriesMatched += $eName
        }
    }
} catch {}

if ($DnsCrackFound) {
    $MasTraceFound = $true
    $dnsString = ($DnsEntriesMatched | Select-Object -Unique) -join ", "
    Write-ResultItem "DNS Client Cache" "PHÁT HIỆN TÊN MIỀN CRACK: $dnsString" "FAILED"
    Add-Finding "MAS Forensics" "DNS Cache" "FAILED" "Máy tính vừa phân giải tên miền máy chủ phân phối công cụ bẻ khóa: $dnsString." "Dấu vết mạng truy cập trang web crack MAS"
} else {
    Write-ResultItem "DNS Client Cache" "Sạch (Không có tên miền get.activated.win/massgrave)" "PASSED"
    Add-Finding "MAS Forensics" "DNS Cache" "PASSED" "DNS Cache sạch." "Bình thường"
}

# 5.4. Quét Tệp Prefetch (GATHEROSSTATE.EXE & CLIPUP.EXE)
$PrefetchParams = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -ErrorAction SilentlyContinue
$PrefetchEnabled = if ($PrefetchParams -and $PrefetchParams.EnablePrefetcher -ne $null) { [int]$PrefetchParams.EnablePrefetcher } else { 0 }
$PrefetchDirExists = Test-Path "$env:windir\Prefetch"

if ($PrefetchEnabled -gt 0 -and $PrefetchDirExists) {
    $PrefetchGatheros = Test-Path "$env:windir\Prefetch\GATHEROSSTATE.EXE-*.pf"
    $PrefetchClipup   = Test-Path "$env:windir\Prefetch\CLIPUP.EXE-*.pf"

    if ($PrefetchGatheros) {
        $MasTraceFound = $true
        Write-ResultItem "Prefetch gatherosstate.exe" "PHÁT HIỆN GATHEROSSTATE TRÊN WINDOWS 10/11!" "FAILED"
        Add-Finding "MAS Forensics" "Gatherosstate Prefetch" "FAILED" "Phát hiện tệp Prefetch của gatherosstate.exe. Công cụ trích xuất vé Win 7/8 này chỉ được script bẻ khóa MAS HWID sử dụng để tạo vé giả mạo trên Win 10/11." "Chứng cứ pháp y giả mạo vé bản quyền kỹ thuật số"
    } else {
        Write-ResultItem "Prefetch gatherosstate.exe" "Sạch (Không phát hiện công cụ trích xuất vé lậu)" "PASSED"
        Add-Finding "MAS Forensics" "Gatherosstate Prefetch" "PASSED" "Không có gatherosstate trong Prefetch." "Bình thường"
    }
} else {
    Write-ResultItem "Prefetch gatherosstate.exe" "Bỏ qua (Prefetcher bị tắt hoặc không khả dụng: EnablePrefetcher=$PrefetchEnabled)" "INFO"
    Add-Finding "MAS Forensics" "Gatherosstate Prefetch" "INFO" "Tính năng Prefetch bị tắt trên hệ thống (EnablePrefetcher=$PrefetchEnabled)." "Không áp dụng"
}

# 5.5. Quét Thư mục vé ClipSVC & Temp Logs của MAS
$GenuineTicketDir = "$env:ProgramData\Microsoft\Windows\ClipSVC\GenuineTicket"
$HasTicketDir = Test-Path $GenuineTicketDir

$TempSearchDirs = @($env:TEMP, "$env:windir\Temp")
$FoundMasLogs = @()
foreach ($td in $TempSearchDirs) {
    if (Test-Path $td) {
        $dbg = "$td\_Debug.log"
        if (Test-Path $dbg) {
            try {
                $content = Get-Content $dbg -Tail 30 -ErrorAction SilentlyContinue
                if ($content -match "HWID Activation|massgrave|ClipSVC|get\.activated\.win|MAS|TSforge") {
                    $FoundMasLogs += $dbg
                }
            } catch {}
        }
        $masDirs = Get-ChildItem -Path $td -Filter "*MAS*" -Directory -ErrorAction SilentlyContinue
        foreach ($md in $masDirs) { $FoundMasLogs += $md.FullName }
    }
}

if ($FoundMasLogs.Count -gt 0) {
    $MasTraceFound = $true
    Write-ResultItem "Tệp nhật ký tạm MAS" "PHÁT HIỆN: $($FoundMasLogs[0])" "FAILED"
    Add-Finding "MAS Forensics" "MAS Temp Logs" "FAILED" "Phát hiện thư mục hoặc tệp log tạm thời của script bẻ khóa MAS: $($FoundMasLogs -join '; ')." "Dấu vết tệp tin bẻ khóa trên ổ đĩa"
} else {
    Write-ResultItem "Tệp nhật ký tạm MAS" "Sạch (Không có tệp log _Debug.log hoặc thư mục MAS rác)" "PASSED"
    Add-Finding "MAS Forensics" "MAS Temp Logs" "PASSED" "Thư mục tạm thời sạch." "Bình thường"
}

# 5.6. Quét Dấu vết TSforge (Ticket Synthesis Forge) & Kho Tokens.dat
$TsforgeFound = $false
$TsforgeDetails = @()

$TokensStorePath = "$env:windir\System32\spp\store\2.0"
$SuspiciousTokenFiles = @("tokens.dat.bak", "tokens.dat.old", "tokens.bar", "tokens_bak.dat", "tokens.dat.tmp")
foreach ($stf in $SuspiciousTokenFiles) {
    $fullTPath = "$TokensStorePath\$stf"
    if (Test-Path $fullTPath) {
        $TsforgeFound = $true
        $TsforgeDetails += "Phát hiện tệp backup/tái tạo tokens lậu: $stf"
    }
}

$MainTokensDat = "$TokensStorePath\tokens.dat"
if (Test-Path $MainTokensDat) {
    $tokensItem = Get-Item $MainTokensDat -ErrorAction SilentlyContinue
    if ($tokensItem -and $tokensItem.Length -lt 500KB) {
        $TsforgeFound = $true
        $TsforgeDetails += "Tệp tokens.dat có dung lượng bất thường ($([math]::Round($tokensItem.Length / 1KB, 1)) KB < 500 KB chuẩn)"
    }
}

$WpaPath = "HKLM:\SYSTEM\WPA"
if (Test-Path $WpaPath) {
    try {
        $wpaKeys = Get-ChildItem -Path $WpaPath -ErrorAction SilentlyContinue
        foreach ($wk in $wpaKeys) {
            if ($wk.Name -match "TSforge|Massgrave|TicketForge") {
                $TsforgeFound = $true
                $TsforgeDetails += "Khóa Registry WPA bất thường: $($wk.Name)"
            }
        }
    } catch {}
}

$RdsGrace = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod"
if (Test-Path $RdsGrace) {
    try {
        $graceVals = Get-ItemProperty -Path $RdsGrace -ErrorAction SilentlyContinue
        if ($graceVals -and ($graceVals.PSObject.Properties | Where-Object { $_.Name -like "*L$*" })) {
            $TsforgeFound = $true
            $TsforgeDetails += "Phát hiện can thiệp gia hạn lậu Terminal Services GracePeriod (TSforge RDS)"
        }
    } catch {}
}

if ($TsforgeFound) {
    $MasTraceFound = $true
    $tsDetailStr = $TsforgeDetails -join "; "
    Write-ResultItem "Dấu vết TSforge / tokens.dat" "PHÁT HIỆN BẤT THƯỜNG: $tsDetailStr" "FAILED"
    Add-Finding "MAS Forensics" "TSforge Artifacts" "FAILED" "Phát hiện dấu vết công nghệ bẻ khóa MAS TSforge (Ticket Synthesis Forge) hoặc can thiệp kho tokens.dat: $tsDetailStr." "Chứng cứ bẻ khóa hệ thống kích hoạt nâng cao"
} else {
    Write-ResultItem "Dấu vết TSforge / tokens.dat" "Sạch (Kho tokens.dat và WPA nguyên bản)" "PASSED"
    Add-Finding "MAS Forensics" "TSforge Artifacts" "PASSED" "Không phát hiện can thiệp kho tokens.dat hay WPA." "Bình thường"
}

# ==============================================================================
# 6. PHÁT HIỆN SppExtComObjHook & CÁC TỆP TIN DLL BẺ KHÓA
# ==============================================================================
Write-Section "6. RÀ SOÁT TỆP HOOK TIẾN TRÌNH (SppExtComObjHook)"

$HookArtifacts = @(
    "$env:windir\System32\SppExtComObjHook.dll",
    "$env:windir\SysWOW64\SppExtComObjHook.dll",
    "$env:windir\SppExtComObjHook.dll",
    "$env:windir\System32\SppExtComObjPatcher.dll",
    "$env:windir\System32\SppExtComObjHook.exe",
    "$env:windir\System32\sppextcomobjhook.dll"
)

$HookFound = $false
foreach ($hookPath in $HookArtifacts) {
    if (Test-Path $hookPath) {
        $HookFound = $true
        Write-ResultItem "Tệp Hook độc hại" "PHÁT HIỆN: $hookPath" "FAILED"
        Add-Finding "Hook Artifacts" "SppExtComObjHook" "FAILED" "Phát hiện tệp hook bẻ khóa: $hookPath. Tệp này được sử dụng bởi KMSpico, KMSAuto Net, AAct để giả mạo kích hoạt." "Chứng cứ bẻ khóa trực tiếp"
    }
}

if (-not $HookFound) {
    Write-ResultItem "Tệp SppExtComObjHook" "Không phát hiện tệp hook nào trong thư mục hệ thống" "PASSED"
    Add-Finding "Hook Artifacts" "SppExtComObjHook" "PASSED" "Thư mục hệ thống sạch, không có thư viện hook can thiệp." "Bình thường"
}

# ==============================================================================
# 7. PHÁT HIỆN CAN THIỆP REGISTRY & IFEO DEBUGGER HIJACKING
# ==============================================================================
Write-Section "7. RÀ SOÁT REGISTRY CAN THIỆP & IFEO DEBUGGER HIJACKING"

$IfeoTarget = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SppExtComObj.exe"
$IfeoOspp = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osppsvc.exe"

$IfeoHijacked = $false

if (Test-Path $IfeoTarget) {
    $prop = Get-ItemProperty -Path $IfeoTarget
    if ($prop.Debugger) {
        $IfeoHijacked = $true
        Write-ResultItem "IFEO Debugger Hijack" "SppExtComObj.exe bị gán Debugger: $($prop.Debugger)" "FAILED"
        Add-Finding "Registry IFEO" "SppExtComObj Debugger" "FAILED" "Tiến trình SppExtComObj.exe bị can thiệp IFEO Debugger trỏ tới: $($prop.Debugger)." "Hành vi can thiệp sâu hệ thống để duy trì bẻ khóa"
    }
}

if (Test-Path $IfeoOspp) {
    $prop = Get-ItemProperty -Path $IfeoOspp
    if ($prop.Debugger) {
        $IfeoHijacked = $true
        Write-ResultItem "IFEO Debugger Hijack" "osppsvc.exe bị gán Debugger: $($prop.Debugger)" "FAILED"
        Add-Finding "Registry IFEO" "osppsvc Debugger" "FAILED" "Tiến trình osppsvc.exe bị can thiệp IFEO Debugger trỏ tới: $($prop.Debugger)." "Bẻ khóa Office/Windows"
    }
}

if (-not $IfeoHijacked) {
    Write-ResultItem "IFEO Debugger Hijack" "Sạch (Không có can thiệp Debugger vào tiến trình bản quyền)" "PASSED"
    Add-Finding "Registry IFEO" "IFEO Debugger" "PASSED" "Không có cấu hình Debugger can thiệp vào tiến trình xác thực." "Bình thường"
}

# Rà soát tính toàn vẹn của Dịch vụ Bảo vệ Bản quyền cốt lõi (SPPSVC - Phát hiện Chew-WGA / RemoveWAT)
$SppCoreSvc = Get-Service -Name "sppsvc" -ErrorAction SilentlyContinue
if (-not $SppCoreSvc -or $SppCoreSvc.StartType -eq "Disabled") {
    Write-ResultItem "Dịch vụ SPPSVC cốt lõi" "BỊ VÔ HIỆU HÓA HOẶC BỊ GỠ BỎ! (Đặc trưng Chew-WGA / RemoveWAT)" "FAILED"
    Add-Finding "Services" "sppsvc Disabled" "FAILED" "Dịch vụ bản quyền Software Protection (sppsvc) bị vô hiệu hóa hoặc không tồn tại. Đây là thủ thuật triệt tiêu hệ thống kiểm tra bản quyền của Chew-WGA / RemoveWAT." "Can thiệp phá hoại dịch vụ hệ thống"
}

$SuspiciousServices = @(
    "KMSEmulator", "AutoKMS", "KMSAuto", "KmsService", "Service_KMS",
    "SECOH-QAD", "KMS-Server", "qad-service", "HEUSvc", "AutoPicoService",
    "KMS-R@1n-Service", "WinDivert", "WinDivert14"
)
$ServiceFound = $false

foreach ($svcName in $SuspiciousServices) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        $ServiceFound = $true
        Write-ResultItem "Dịch vụ bẻ khóa (Service)" "TÌM THẤY DỊCH VỤ: $svcName (Trạng thái: $($svc.Status))" "FAILED"
        Add-Finding "Services" $svcName "FAILED" "Hệ thống đang chạy dịch vụ bẻ khóa bản quyền ngầm: $svcName." "Phần mềm trái phép đang hoạt động thường trực"
    }
}

if (-not $ServiceFound) {
    Write-ResultItem "Dịch vụ bẻ khóa (Service)" "Không phát hiện dịch vụ KMS crack nào đang chạy" "PASSED"
    Add-Finding "Services" "Crack Services" "PASSED" "Không có dịch vụ KMS emulator nào tồn tại." "Bình thường"
}

$RegOrgPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$RegOrg = (Get-ItemProperty -Path $RegOrgPath).RegisteredOrganization
$RegOwner = (Get-ItemProperty -Path $RegOrgPath).RegisteredOwner
$PirateTags = @("ghoster", "ghostviet", "khatmau", "songngoc", "thuannguyen", "lehait", "ghost", "repack", "lite", "crack")

$GhostDetected = $false
foreach ($tag in $PirateTags) {
    if ($RegOrg -like "*$tag*" -or $RegOwner -like "*$tag*") {
        $GhostDetected = $true
        Write-ResultItem "Dấu hiệu Ghost Win dạo" "Phát hiện chuỗi nhận diện Ghost: Org='$RegOrg' / Owner='$RegOwner'" "WARNING"
        Add-Finding "Ghost/Repack" "Registered Info" "WARNING" "Thông tin người dùng đăng ký mang dấu hiệu của bản Ghost lậu phân tán trên Internet: Org='$RegOrg', Owner='$RegOwner'." "Rủi ro cài đặt từ nguồn không chính thức"
        break
    }
}

if (-not $GhostDetected) {
    Write-ResultItem "Thông tin bản quyền Windows" "Chủ sở hữu: '$RegOwner' / Tổ chức: '$RegOrg'" "PASSED"
    Add-Finding "Ghost/Repack" "Registered Info" "PASSED" "Thông tin đăng ký bình thường." "Hợp lệ"
}

# ==============================================================================
# 8. QUÉT THƯ MỤC & CÔNG CỤ BẺ KHÓA TRÊN ĐĨA CỨNG
# ==============================================================================
Write-Section "8. QUÉT CÔNG CỤ & TỆP TIN BẺ KHÓA (KMSpico, AutoKMS, KMSAuto, MAS...)"

$CrackPaths = @(
    "$env:ProgramFiles\KMSpico",
    "${env:ProgramFiles(x86)}\KMSpico",
    "$env:windir\AutoKMS",
    "$env:ProgramData\KMSAuto",
    "$env:ProgramData\KMSAutoS",
    "$env:ProgramFiles\KMSAuto Net",
    "${env:ProgramFiles(x86)}\KMSAuto Net",
    "$env:ProgramData\Microsoft Toolkit",
    "$env:ProgramFiles\Microsoft Toolkit",
    "$env:windir\KMS-R@1n",
    "$env:windir\AAct.exe",
    "$env:windir\AAct_x64.exe",
    "$env:windir\ConsoleAct.exe",
    "$env:windir\ConsoleAct_x64.exe",
    "$env:ProgramData\AAct",
    "$env:ProgramData\ConsoleAct",
    "$env:ProgramData\W10DigitalActivation",
    "$env:ProgramData\HEU_KMS",
    "$env:ProgramFiles\HEU KMS Activator",
    "${env:ProgramFiles(x86)}\HEU KMS Activator",
    "$env:SystemDrive\grldr",
    "$env:SystemDrive\menu.lst",
    "$env:windir\System32\drivers\slic.sys",
    "$env:windir\System32\drivers\windivert64.sys",
    "$env:windir\System32\drivers\windivert32.sys",
    "$env:windir\System32\wat\watadmin.exe",
    "$env:windir\Setup\Scripts\SetupComplete.cmd",
    "$env:windir\Setup\Scripts\ErrorHandler.cmd",
    "$env:windir\Setup\Scripts\Activate.cmd",
    "$env:windir\Setup\Scripts\Activate.bat"
)

$CrackFoundOnDisk = $false
foreach ($cPath in $CrackPaths) {
    if (Test-Path $cPath) {
        $CrackFoundOnDisk = $true
        $isDir = (Get-Item $cPath) -is [System.IO.DirectoryInfo]
        $typeStr = if ($isDir) { "Thư mục" } else { "Tệp tin" }

        $detailStr = "Tồn tại $typeStr công cụ bẻ khóa: $cPath"
        if (-not $isDir -and $cPath -like "*SetupComplete.cmd*") {
            $content = Get-Content $cPath -Raw
            if ($content -match "slmgr|massgrave|kms|ohook|activate") {
                $detailStr += " (Chứa lệnh kích hoạt lậu tự động khi cài Win)"
            }
        }

        Write-ResultItem "Dấu vết Crack trên đĩa" "$typeStr : $cPath" "FAILED"
        Add-Finding "Crack Files" ([System.IO.Path]::GetFileName($cPath)) "FAILED" $detailStr "Lưu trữ/sử dụng công cụ bẻ khóa bản quyền trái phép theo NĐ 341/2025/NĐ-CP"
    }
}

if (-not $CrackFoundOnDisk) {
    Write-ResultItem "Dấu vết Crack trên đĩa" "Không tìm thấy thư mục hoặc tệp công cụ crack phổ biến nào" "PASSED"
    Add-Finding "Crack Files" "Known HackTools" "PASSED" "Không phát hiện thư mục cài đặt của KMSpico, AutoKMS, KMSAuto, Toolkit..." "Bình thường"
}

# ==============================================================================
# 9. QUÉT TÁC VỤ ĐẶT LỊCH (SCHEDULED TASKS) DUY TRÌ BẢN QUYỀN LẬU
# ==============================================================================
Write-Section "9. RÀ SOÁT TÁC VỤ LÊN LỊCH TỰ ĐỘNG RE-ARM (SCHEDULED TASKS)"

$SuspiciousTaskPatterns = @("AutoKMS", "KMSpico", "KMSAuto", "AAct", "AutoPico", "HEU", "CleanKMS", "KMSCleaner", "Ratiborus", "W10Digital", "ConsoleAct", "SppExtComObj")
$TasksFound = $false

try {
    $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($task in $allTasks) {
        foreach ($pattern in $SuspiciousTaskPatterns) {
            if ($task.TaskName -like "*$pattern*" -or $task.TaskPath -like "*$pattern*") {
                $TasksFound = $true
                Write-ResultItem "Tác vụ bẻ khóa (Task)" "TÌM THẤY: $($task.TaskPath)$($task.TaskName)" "FAILED"
                Add-Finding "Scheduled Tasks" $task.TaskName "FAILED" "Phát hiện tác vụ tự động kích hoạt lại Windows lậu theo chu kỳ: $($task.TaskPath)$($task.TaskName)." "Duy trì hành vi bẻ khóa ngầm định kỳ"
            }
        }
    }
} catch {}

if (-not $TasksFound) {
    Write-ResultItem "Tác vụ bẻ khóa (Task)" "Không phát hiện tác vụ tự động gia hạn lậu nào" "PASSED"
    Add-Finding "Scheduled Tasks" "KMS Tasks" "PASSED" "Hệ thống tác vụ sạch, không có AutoKMS/KMSpico Tasks." "Bình thường"
}

# ==============================================================================
# 10. KIỂM TRA DANH SÁCH LOẠI TRỪ CỦA WINDOWS DEFENDER (DEFENDER EXCLUSIONS)
# ==============================================================================
Write-Section "10. KIỂM TRA LOẠI TRỪ CỦA WINDOWS DEFENDER (DEFENDER TAMPERING)"

if ($IsAdmin) {
    try {
        $mpPref = Get-MpPreference -ErrorAction Stop
        $exclPaths = $mpPref.ExclusionPath
        $exclProcs = $mpPref.ExclusionProcess

        $DefenderTampered = $false
        $CrackPatterns = @("AutoKMS", "KMSpico", "KMSAuto", "AAct", "SppExtComObj", "MAS", "Activator", "Ratiborus", "HEU", "ConsoleAct", "W10Digital", "windivert", "KMSCleaner", "DefenderControl")

        if ($exclPaths) {
            foreach ($ep in $exclPaths) {
                foreach ($cp in $CrackPatterns) {
                    if ($ep -like "*$cp*") {
                        $DefenderTampered = $true
                        Write-ResultItem "Loại trừ Defender (Path)" "Phát hiện đường dẫn hacktool được miễn quét: $ep" "FAILED"
                        Add-Finding "Defender Exclusions" "Thư mục loại trừ" "FAILED" "Đường dẫn bẻ khóa '$ep' đã được thêm vào danh sách bỏ qua của Antivirus nhằm tránh bị xóa." "Cố tình tắt tính năng bảo mật để duy trì crack"
                    }
                }
            }
        }

        if ($exclProcs) {
            foreach ($proc in $exclProcs) {
                foreach ($cp in $CrackPatterns) {
                    if ($proc -like "*$cp*") {
                        $DefenderTampered = $true
                        Write-ResultItem "Loại trừ Defender (Proc)" "Phát hiện tiến trình hacktool được miễn quét: $proc" "FAILED"
                        Add-Finding "Defender Exclusions" "Tiến trình loại trừ" "FAILED" "Tiến trình '$proc' được loại trừ khỏi Defender." "Cố tình can thiệp an ninh"
                    }
                }
            }
        }

        if (-not $DefenderTampered) {
            Write-ResultItem "Cấu hình Windows Defender" "Không phát hiện loại trừ đáng ngờ liên quan đến công cụ bẻ khóa" "PASSED"
            Add-Finding "Defender Exclusions" "Defender Settings" "PASSED" "Không có cấu hình ngoại lệ cho công cụ bẻ khóa." "Bình thường"
        }
    } catch {
        Write-ResultItem "Cấu hình Windows Defender" "Không thể truy xuất cấu hình Defender ($($_.Exception.Message))" "WARNING"
        Add-Finding "Defender Exclusions" "Defender Query" "WARNING" "Không truy vấn được Get-MpPreference." "Cần kiểm tra thủ công"
    }
} else {
    Write-ResultItem "Cấu hình Windows Defender" "Bỏ qua (Yêu cầu quyền Administrator để đọc cấu hình Defender)" "SUSPICIOUS"
    Add-Finding "Defender Exclusions" "Defender Access" "SUSPICIOUS" "Không đủ quyền Administrator để đọc danh sách loại trừ Defender." "Chưa quét được"
}

# ==============================================================================
# 11. KIỂM TRA CAN THIỆP FILE HOSTS (CHUYỂN HƯỚNG MÁY CHỦ BẢN QUYỀN)
# ==============================================================================
Write-Section "11. RÀ SOÁT TỆP TIN HOSTS (CHUYỂN HƯỚNG MÁY CHỦ MICROSOFT)"

$HostsPath = "$env:windir\System32\drivers\etc\hosts"
$HostsTampered = $false

if (Test-Path $HostsPath) {
    $hostsLines = Get-Content $HostsPath
    $TargetDomains = @("sls.microsoft.com", "licensing.mp.microsoft.com", "validation.sls.microsoft.com", "activation.sls.microsoft.com")

    foreach ($line in $hostsLines) {
        $trimmed = $line.Trim()
        if ($trimmed.StartsWith("#") -or [string]::IsNullOrWhiteSpace($trimmed)) { continue }

        foreach ($td in $TargetDomains) {
            if ($trimmed -like "*$td*") {
                $HostsTampered = $true
                Write-ResultItem "Can thiệp File Hosts" "Phát hiện dòng chặn/chuyển hướng: $trimmed" "FAILED"
                Add-Finding "Hosts File" "Microsoft Licensing Redirection" "FAILED" "Tệp hosts bị can thiệp để chặn hoặc chuyển hướng máy chủ xác thực bản quyền: $trimmed." "Hành vi gian lận kỹ thuật số"
            }
        }
    }
}

if (-not $HostsTampered) {
    Write-ResultItem "Kiểm tra File Hosts" "Sạch (Không có mục chuyển hướng máy chủ bản quyền Microsoft)" "PASSED"
    Add-Finding "Hosts File" "Hosts Integrity" "PASSED" "Tệp hosts không bị chỉnh sửa cho mục đích bẻ khóa." "Bình thường"
}

# ==============================================================================
# 12. ĐỐI SOÁT HÓA ĐƠN ĐIỆN TỬ VAT THỰC TẾ (INVOICE PROCUREMENT AUDIT)
# ==============================================================================
Write-Section "12. ĐỐI SOÁT HÓA ĐƠN ĐIỆN TỬ VAT THỰC TẾ (NGHỊ ĐỊNH 341/2025/NĐ-CP)"

$MatchedInvoice = $null
$InvoiceStatusDetails = ""
$InvoiceDatabase = [System.Collections.Generic.List[PSObject]]::new()

function Test-IsPlaceholderInvoice {
    param ($inv)
    if (-not $inv) { return $false }
    $bName = if ($inv.BuyerName) { $inv.BuyerName.ToString().ToUpper() } else { "" }
    $bTax  = if ($inv.BuyerTaxId) { $inv.BuyerTaxId.ToString().Trim() } else { "" }
    if ($bName -match "DOANH NGHIỆP CỦA BẠN|CONG TY CUA BAN|YOUR COMPANY|EXAMPLE CORP|TEN CONG TY") {
        return $true
    }
    if ($bTax -in @("0109876543", "109876543", "0123456789", "1234567890")) {
        return $true
    }
    return $false
}

# Nguồn 1: Fetch qua REST API nội bộ doanh nghiệp nếu được cung cấp
if ($InvoiceApiUrl) {
    try {
        $queryUri = "$InvoiceApiUrl`?hostname=$([System.Uri]::EscapeDataString($ComputerName))&serial=$([System.Uri]::EscapeDataString($HardwareSerial))&key=$([System.Uri]::EscapeDataString($PartialKey))"
        if ($ExpectedTaxId) { $queryUri += "&taxId=$([System.Uri]::EscapeDataString($ExpectedTaxId))" }
        Write-ResultItem "API Hóa đơn (REST)" "Đang kết nối: $InvoiceApiUrl..." "INFO"
        $apiResp = Invoke-RestMethod -Uri $queryUri -Method Get -TimeoutSec 10 -ErrorAction Stop
        if ($apiResp) {
            if ($apiResp -is [System.Array]) {
                foreach ($item in $apiResp) { $InvoiceDatabase.Add($item) }
            } else {
                $InvoiceDatabase.Add($apiResp)
            }
            Write-ResultItem "API Hóa đơn (REST)" "Đã tải về $($InvoiceDatabase.Count) bản ghi chứng từ từ máy chủ" "PASSED"
        }
    } catch {
        Write-ResultItem "API Hóa đơn (REST)" "Lỗi kết nối máy chủ API ($($_.Exception.Message))" "WARNING"
        Add-Finding "Invoice Audit" "Invoice API" "WARNING" "Không thể kết nối đến máy chủ quản lý hóa đơn $InvoiceApiUrl." "Cần kiểm tra mạng nội bộ"
    }
}

# Nguồn 2: Đọc file danh mục hóa đơn cục bộ hoặc mạng nội bộ
$ResolvedInvoiceFile = ""
if ($InvoiceFile -and (Test-Path $InvoiceFile)) {
    $ResolvedInvoiceFile = $InvoiceFile
} else {
    $DefaultCandidates = @(
        ".\invoices.json",
        ".\invoices.csv",
        "$PSScriptRoot\invoices.json",
        "$PSScriptRoot\invoices.csv",
        "C:\Audit\invoices.json",
        "C:\Audit\invoices.csv"
    )
    foreach ($cand in $DefaultCandidates) {
        if (Test-Path $cand) {
            $ResolvedInvoiceFile = $cand
            break
        }
    }
}

$HasOnlyPlaceholders = $false
if ($ResolvedInvoiceFile) {
    Write-ResultItem "Kho Hóa đơn (File)" "Đang nạp dữ liệu: $ResolvedInvoiceFile" "INFO"
    try {
        if ($ResolvedInvoiceFile -like "*.json") {
            $jsonData = Get-Content $ResolvedInvoiceFile -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($jsonData -is [System.Array]) {
                foreach ($entry in $jsonData) { $InvoiceDatabase.Add($entry) }
            } elseif ($jsonData) {
                $InvoiceDatabase.Add($jsonData)
            }
        } elseif ($ResolvedInvoiceFile -like "*.csv") {
            $csvData = Import-Csv $ResolvedInvoiceFile -Encoding UTF8
            foreach ($entry in $csvData) { $InvoiceDatabase.Add($entry) }
        }
        
        $placeholderCount = @($InvoiceDatabase | Where-Object { Test-IsPlaceholderInvoice $_ }).Count
        if ($placeholderCount -eq $InvoiceDatabase.Count -and $InvoiceDatabase.Count -gt 0) {
            $HasOnlyPlaceholders = $true
            Write-ResultItem "Kho Hóa đơn (File)" "CẢNH BÁO: Tệp hóa đơn chỉ chứa dữ liệu mẫu giả định (Placeholder: 'CÔNG TY DOANH NGHIỆP CỦA BẠN')!" "WARNING"
            Add-Finding "Invoice Audit" "Placeholder Invoices" "WARNING" "Tệp hóa đơn ($ResolvedInvoiceFile) là file mẫu mặc định của dự án. Bỏ qua việc tự động ghép hóa đơn để tránh cấp chứng nhận sai lệch cho máy chưa cấu hình hóa đơn thật." "Chưa cấu hình hóa đơn thực tế của doanh nghiệp"
        } else {
            Write-ResultItem "Kho Hóa đơn (File)" "Đã nạp thành công $($InvoiceDatabase.Count) chứng từ hóa đơn" "PASSED"
        }
    } catch {
        Write-ResultItem "Kho Hóa đơn (File)" "Lỗi đọc tệp hóa đơn: $($_.Exception.Message)" "WARNING"
    }
}

# Tiến hành đối soát máy tính hiện tại với cơ sở dữ liệu hóa đơn
if ($InvoiceDatabase.Count -gt 0 -and -not $HasOnlyPlaceholders) {
    # Vòng 1: Tìm hóa đơn khớp trực tiếp phần cứng / thiết bị
    foreach ($inv in $InvoiceDatabase) {
        if (Test-IsPlaceholderInvoice $inv) { continue }

        # 1. Khớp theo Service Tag / Serial phần cứng
        if ($inv.TargetIdentifier -and $HardwareSerial -ne "Unknown" -and -not ($HardwareSerial -like "*VMware*") -and ($inv.TargetIdentifier.ToString().Trim().ToUpper() -eq $HardwareSerial.ToUpper())) {
            $MatchedInvoice = $inv
            $InvoiceStatusDetails = "Khớp chính xác Service Tag/Serial phần cứng máy: $HardwareSerial"
            break
        }
        # 2. Khớp theo Tên máy tính (Hostname)
        elseif ($inv.TargetIdentifier -and -not ($ComputerName -like "DESKTOP-*") -and ($inv.TargetIdentifier.ToString().Trim().ToUpper() -eq $ComputerName.ToUpper())) {
            $MatchedInvoice = $inv
            $InvoiceStatusDetails = "Khớp chính xác Tên máy tính (Hostname): $ComputerName"
            break
        }
        # 3. Khớp theo khóa bản quyền phần cứng riêng lẻ (Không khớp Generic Key)
        elseif ($inv.TargetKey -and -not $IsGenericKey -and (($Oa3Key -and $inv.TargetKey -like "*$Oa3Key*") -or ($PartialKey -ne "None" -and $inv.TargetKey -like "*$PartialKey*"))) {
            $MatchedInvoice = $inv
            $InvoiceStatusDetails = "Khớp khóa bản quyền riêng biệt: $(if ($Oa3Key) { $Oa3Key } else { $PartialKey })"
            break
        }
    }

    # Vòng 2: Nếu chưa có hóa đơn riêng lẻ, tìm hóa đơn gói bản quyền tập trung doanh nghiệp (Enterprise Pool)
    if (-not $MatchedInvoice) {
        foreach ($inv in $InvoiceDatabase) {
            if (Test-IsPlaceholderInvoice $inv) { continue }
            if ($inv.TargetIdentifier -and ($inv.TargetIdentifier.ToString().ToUpper() -eq "ALL_ENTERPRISE_POOL")) {
                $CanClaimPool = $false
                $PoolReason = ""

                if ($ExpectedTaxId -and $inv.BuyerTaxId -and ($inv.BuyerTaxId.Trim() -eq $ExpectedTaxId.Trim())) {
                    $CanClaimPool = $true
                    $PoolReason = "Xác thực qua Mã số thuế doanh nghiệp ($ExpectedTaxId)"
                } elseif ($DomainJoined) {
                    $CanClaimPool = $true
                    $PoolReason = "Xác thực qua máy trạm thuộc Active Directory Domain ($DomainName)"
                }

                if ($CanClaimPool) {
                    $MatchedInvoice = $inv
                    $InvoiceStatusDetails = "Nằm trong Hợp đồng/Hóa đơn mua gói bản quyền tập trung toàn doanh nghiệp ($PoolReason)"
                    break
                } else {
                    Write-ResultItem "Đối soát Enterprise Pool" "Từ chối ghép Hóa đơn gói tập trung: Máy tính Workgroup/Máy ảo không có Domain hoặc MST xác thực" "WARNING"
                    Add-Finding "Invoice Audit" "Enterprise Pool Rejected" "WARNING" "Không thể áp dụng Hóa đơn gói tập trung ($($inv.InvoiceNumber)) cho thiết bị này vì máy đang ở Workgroup cá nhân và không có tham số xác minh Mã số thuế (-ExpectedTaxId)." "Cần xác thực quyền sở hữu doanh nghiệp"
                }
            }
        }
    }
}

# Đánh giá tính hợp lệ của hóa đơn tìm được
if ($MatchedInvoice) {
    $invNum = $MatchedInvoice.InvoiceNumber
    $invSeries = $MatchedInvoice.InvoiceSeries
    $invDate = $MatchedInvoice.InvoiceDate
    $invVendor = $MatchedInvoice.VendorName
    $invBuyer = $MatchedInvoice.BuyerName
    $invBuyerTaxId = $MatchedInvoice.BuyerTaxId
    $invItem = $MatchedInvoice.ItemName
    $invEdition = $MatchedInvoice.LicenseEdition

    Write-ResultItem "Hóa đơn đối ứng tìm thấy" "Số HĐ: $invNum | Ký hiệu: $invSeries | Ngày: $invDate" "PASSED"
    Write-ResultItem "Đơn vị bán hàng (Vendor)" "$invVendor (MST: $($MatchedInvoice.VendorTaxId))" "INFO"
    Write-ResultItem "Đơn vị mua hàng (Buyer)" "$invBuyer (MST: $invBuyerTaxId)" "INFO"
    Write-ResultItem "Nội dung mặt hàng trên HĐ" "$invItem" "INFO"

    $EditionMismatch = $false
    if ($OSCaption -like "*Pro*" -and $invEdition -and $invEdition -like "*Home*") {
        $EditionMismatch = $true
    }

    $ChannelMismatch = $false
    if ($IsGenericKey -and $IsVirtualMachine -and $MatchedInvoice.LicenseType -match "CSP|Volume") {
        $ChannelMismatch = $true
    }

    $TaxIdMismatch = $false
    if ($ExpectedTaxId -and $invBuyerTaxId -and ($invBuyerTaxId.Trim() -ne $ExpectedTaxId.Trim())) {
        $TaxIdMismatch = $true
    }

    if ($EditionMismatch) {
        Write-ResultItem "Xác thực Hóa đơn" "LỆCH PHIÊN BẢN: Máy chạy Windows Pro nhưng hóa đơn chỉ mua Windows Home!" "FAILED"
        Add-Finding "Invoice Audit" "Edition Mismatch" "FAILED" "Thiết bị đang cài Windows Pro nhưng hóa đơn số $invNum chỉ cấp phép bản Home. Đây là lỗi vi phạm bản quyền bị phạt rất nặng theo NĐ 341/2025/NĐ-CP." "Vi phạm bản quyền do nâng cấp trái phép"
    } elseif ($ChannelMismatch) {
        Write-ResultItem "Xác thực Hóa đơn" "LỆCH KÊNH BẢN QUYỀN: Hóa đơn là gói CSP/Volume nhưng máy lại kích hoạt bằng Retail Generic Key ($PartialKey)!" "WARNING"
        Add-Finding "Invoice Audit" "Channel Mismatch" "WARNING" "Hóa đơn là gói doanh nghiệp (CSP/Volume), nhưng máy trạm lại kích hoạt qua kênh Retail cá nhân bằng Generic Key ($PartialKey). Điều này xảy ra khi máy chưa được gán license bản quyền từ CSP portal mà bị bẻ khóa MAS HWID lậu." "Rủi ro bị bác bỏ khi thanh tra"
    } elseif ($TaxIdMismatch) {
        Write-ResultItem "Xác thực Hóa đơn" "MÃ SỐ THUẾ KHÔNG KHỚP: MST trên hóa đơn ($invBuyerTaxId) khác MST doanh nghiệp ($ExpectedTaxId)!" "WARNING"
        Add-Finding "Invoice Audit" "Tax ID Mismatch" "WARNING" "Hóa đơn số $invNum đứng tên MST khác ($invBuyerTaxId). Không chứng minh được tài sản thuộc quyền sở hữu của doanh nghiệp bạn." "Nguy cơ bị loại trừ chứng từ hợp lệ"
    } else {
        Write-ResultItem "Xác thực Hóa đơn" "HỢP LỆ VÀ ĐẦY ĐỦ PHÁP LÝ (Khớp: $InvoiceStatusDetails)" "PASSED"
        Add-Finding "Invoice Audit" "VAT Invoice Verified" "PASSED" "Đã đối soát thành công Hóa đơn điện tử VAT Số: $invNum, Ký hiệu: $invSeries, Ngày: $invDate từ nhà cung cấp $invVendor. Đạt chuẩn chứng từ theo Nghị định 341/2025/NĐ-CP." "Đầy đủ chứng từ pháp lý xuất trình thanh tra"
    }
} else {
    $invNotice = if ($HasOnlyPlaceholders) { "TỆP HÓA ĐƠN CHỈ LÀ DỮ LIỆU MẪU MẶC ĐỊNH (CẦN CẤU HÌNH HÓA ĐƠN THẬT)" } else { "CHƯA TÌM THẤY HÓA ĐƠN ĐỐI ỨNG TRONG KHO DỮ LIỆU" }
    Write-ResultItem "Đối soát Hóa đơn VAT" $invNotice $(if ($RequireInvoice) { "WARNING" } else { "SUSPICIOUS" })
    Add-Finding "Invoice Audit" "Missing VAT Invoice" $(if ($RequireInvoice) { "WARNING" } else { "SUSPICIOUS" }) "Chưa tìm thấy hóa đơn GTGT hoặc hợp đồng cấp phép phần mềm hợp lệ cho thiết bị này (Serial: $HardwareSerial, Hostname: $ComputerName)." "Theo Nghị định 341/2025/NĐ-CP, không xuất trình được hóa đơn tài chính khi thanh tra sẽ bị xử phạt vi phạm hành chính"
}

# ==============================================================================
# 13. TỔNG HỢP ĐÁNH GIÁ PHÁP LÝ & KẾT LUẬN TUÂN THỦ (NGHỊ ĐỊNH 341/2025/NĐ-CP)
# ==============================================================================
Write-Section "13. KẾT LUẬN TUÂN THỦ & ĐÁNH GIÁ RỦI RO PHÁP LÝ DOANH NGHIỆP"

$CountFailed = @($AuditFindings | Where-Object { $_.Status -eq "FAILED" }).Count
$CountWarning = @($AuditFindings | Where-Object { $_.Status -eq "WARNING" }).Count
$CountSuspicious = @($AuditFindings | Where-Object { $_.Status -eq "SUSPICIOUS" }).Count
$CountPassed = @($AuditFindings | Where-Object { $_.Status -eq "PASSED" }).Count

$TechSuspicious = @($AuditFindings | Where-Object { $_.Status -in @("SUSPICIOUS", "WARNING") -and $_.Category -ne "Defender Exclusions" -and $_.Category -ne "Script Execution" -and $_.Category -ne "Invoice Audit" -and $_.Category -ne "Hardware Platform" }).Count
$HasInvoicePassed = ($MatchedInvoice -ne $null -and @($AuditFindings | Where-Object { $_.Item -eq "VAT Invoice Verified" -and $_.Status -eq "PASSED" }).Count -gt 0)

$FinalVerdict = "GENUINE_COMPLIANT"
$VerdictTitle = "ĐẠT CHUẨN TUÂN THỦ (GENUINE / COMPLIANT)"
$VerdictColor = "Green"
$ExitCode = 0
$ActionGuidance = ""

if ($CountFailed -gt 0) {
    $FinalVerdict = "CRITICAL_PIRATED_CRACKED"
    $VerdictTitle = "NGUY CƠ CAO: PHÁT HIỆN SỬ DỤNG WINDOWS LẬU / CÔNG CỤ BẺ KHÓA (MAS/HWID/KMS)"
    $VerdictColor = "Red"
    $ExitCode = 3

    $failedItemsSummary = ($AuditFindings | Where-Object { $_.Status -eq "FAILED" } | ForEach-Object { "- $($_.Category) [$($_.Item)]: $($_.Details)" }) -join "`r`n"

    $ActionGuidance = @"
[CẢNH BÁO PHÁP LÝ KHẨN CẤP CHO DOANH NGHIỆP THEO NGHỊ ĐỊNH 341/2025/NĐ-CP]:
1. HỆ THỐNG ĐÃ PHÁT HIỆN CÁC DẤU VẾT BẺ KHÓA VÀ GIAN LẬN BẢN QUYỀN SAU:
$failedItemsSummary

2. RỦI RO PHÁP LÝ:
   - Theo Nghị định 341/2025/NĐ-CP và Điều 225 Bộ luật Hình sự, việc sử dụng các công cụ bẻ khóa (MAS, HWID, KMS, Ohook)
     bị coi là hành vi cố ý can thiệp trái phép vào hệ điều hành và vi phạm quyền tác giả đối với pháp nhân thương mại.
   - Màn hình hiển thị 'Windows is activated' hoàn toàn vô giá trị khi chữ ký bẻ khóa và lịch sử dòng lệnh bị bóc tách.

3. HÀNH ĐỘNG KHẮC PHỤC NGAY LẬP TỨC:
   - Xóa bỏ lịch sử dòng lệnh và các tệp script bẻ khóa tồn lưu.
   - Gỡ bỏ product key lậu bằng lệnh Administrator: 'slmgr.vbs /upk' và 'slmgr.vbs /cpky'.
   - Nếu máy tính vật lý có OEM Key trong BIOS (MSDM: $Oa3Key): Chạy 'slmgr.vbs /ipk $Oa3Key' và 'slmgr.vbs /ato' để hoàn nguyên bản quyền hợp pháp.
   - Nếu là máy ảo ($VmPlatform) hoặc máy không có OEM key: Mua giấy phép bản quyền Windows Pro chính hãng (Microsoft CSP/ESD) có đầy đủ Hóa đơn GTGT (VAT) và mã định danh doanh nghiệp.
"@
} elseif ($LicenseStatusCode -ne 1) {
    $FinalVerdict = "NON_COMPLIANT_UNLICENSED"
    $VerdictTitle = "KHÔNG TUÂN THỦ: WINDOWS CHƯA ĐƯỢC KÍCH HOẠT HỢP LỆ"
    $VerdictColor = "Red"
    $ExitCode = 2
    $ActionGuidance = @"
[CẢNH BÁO BẢN QUYỀN]:
1. Windows trên máy chưa được kích hoạt hoặc đang trong thời gian gia hạn dùng thử (Grace Period).
2. Việc sử dụng phần mềm trong hoạt động kinh doanh mà không có giấy phép bản quyền vi phạm Luật Sở hữu trí tuệ.
3. HÀNH ĐỘNG KHẮC PHỤC:
   - Liên hệ bộ phận Mua sắm/IT để cấp bản quyền Windows chính hãng (có hóa đơn VAT) và kích hoạt ngay.
"@
} elseif ($RequireInvoice -and -not $HasInvoicePassed) {
    $FinalVerdict = "WARNING_MISSING_INVOICE"
    $VerdictTitle = "CẢNH BÁO: CHƯA CÓ HÓA ĐƠN ĐIỆN TỬ VAT ĐỐI ỨNG CHO THIẾT BỊ"
    $VerdictColor = "Magenta"
    $ExitCode = 1
    $ActionGuidance = @"
[RỦI RO PHÁP LÝ THEO NGHỊ ĐỊNH 341/2025/NĐ-CP - THIẾU HÓA ĐƠN ĐỐI ỨNG]:
1. Về mặt kỹ thuật: Windows trên máy đã kích hoạt và không chứa công cụ crack.
2. Về mặt PHÁP LÝ CHỨNG TỪ: Doanh nghiệp CHƯA LIÊN KẾT ĐƯỢC HÓA ĐƠN GTGT (VAT) chứng minh nguồn gốc mua hàng hợp pháp cho thiết bị này (Serial: $HardwareSerial).
3. Theo quy định của Nghị định 341/2025/NĐ-CP, việc không xuất trình được hóa đơn tài chính hợp pháp tại thời điểm thanh tra
   sẽ bị coi là hành vi sử dụng phần mềm không phép và có nguy cơ bị xử phạt hành chính.
4. HÀNH ĐỘNG KHẮC PHỤC:
   - Cập nhật số hóa đơn vào file 'invoices.json' / 'invoices.csv' của công ty để hoàn thiện hồ sơ thanh tra.
"@
} elseif ($TechSuspicious -gt 0) {
    $FinalVerdict = "SUSPICIOUS_UNVERIFIED"
    $VerdictTitle = "CẦN XÁC MINH: CẦN ĐỐI SOÁT HÓA ĐƠN / HỢP ĐỒNG BẢN QUYỀN"
    $VerdictColor = "Yellow"
    $ExitCode = 1
    $ActionGuidance = @"
[LƯU Ý ĐỐI SOÁT CHỨNG TỪ DOANH NGHIỆP]:
1. Hệ thống đang báo đã kích hoạt, tuy nhiên đang sử dụng Generic Key ($PartialKey) không có OEM BIOS, hoặc Volume KMS chưa rõ nguồn gốc.
2. Về mặt pháp lý: Đoàn thanh tra bản quyền BẮT BUỘC kiểm tra:
   - Hóa đơn tài chính (Hóa đơn điện tử VAT) chứng minh việc mua bản quyền.
   - Hợp đồng thỏa thuận cấp phép số lượng lớn (Volume Licensing / Enterprise Agreement / CSP).
3. HÀNH ĐỘNG KHẮC PHỤC:
   - Bộ phận IT phối hợp cùng Kế toán kiểm tra lại hồ sơ chứng từ lưu trữ của thiết bị này.
"@
} else {
    $FinalVerdict = "GENUINE_COMPLIANT"
    $VerdictTitle = if ($HasInvoicePassed) {
        "ĐẠT CHUẨN TUÂN THỦ 100%: BẢN QUYỀN WINDOWS HỢP LỆ & ĐÃ ĐỐI SOÁT HÓA ĐƠN VAT"
    } else {
        "ĐẠT CHUẨN KỸ THUẬT: BẢN QUYỀN HỢP LỆ & SẠCH CÔNG CỤ CRACK (CẦN LƯU TRỮ HÓA ĐƠN)"
    }
    $VerdictColor = "Green"
    $ExitCode = 0
    
    $invClause = if ($HasInvoicePassed) {
        "3. [XÁC THỰC THÀNH CÔNG]: Thiết bị đã được liên kết với Hóa đơn điện tử VAT hợp lệ (Số: $($MatchedInvoice.InvoiceNumber), Ngày: $($MatchedInvoice.InvoiceDate) của $($MatchedInvoice.VendorName)). ĐẦY ĐỦ HỒ SƠ PHÁP LÝ ĐỂ XUẤT TRÌNH THANH TRA."
    } else {
        "3. [LƯU Ý CHỨNG TỪ]: Doanh nghiệp cần đảm bảo lưu giữ Hóa đơn VAT / Thỏa thuận mua bản quyền tương ứng với thiết bị này (Serial: $HardwareSerial) trong hồ sơ kế toán."
    }

    $ActionGuidance = @"
[ĐÁNH GIÁ PHÁP LÝ THEO NGHỊ ĐỊNH 341/2025/NĐ-CP]:
1. Hệ điều hành đã kích hoạt hợp pháp qua kênh chính thức ($ProductKeyChannel), các file hệ thống và chữ ký số nguyên bản của Microsoft.
2. Không phát hiện bất kỳ dấu vết công cụ bẻ khóa (MAS, HWID, KMS38, Ohook), DLL Hook, máy chủ KMS lạ hay tác vụ can thiệp ngầm.
$invClause
"@
}

if (-not $Quiet) {
    Write-Host ""
    Write-Host ("*" * 80) -ForegroundColor $VerdictColor
    Write-Host "  KẾT QUẢ CUỐI CÙNG : $VerdictTitle" -ForegroundColor $VerdictColor
    Write-Host "  MÃ ĐÁNH GIÁ       : $FinalVerdict" -ForegroundColor White
    Write-Host "  MÃ THOÁT (EXIT)   : $ExitCode" -ForegroundColor White
    Write-Host ("  TỔNG HỢP CHỈ SỐ   : {0} Đạt | {1} Cần xác minh | {2} Cảnh báo | {3} Vi phạm nghiêm trọng" -f $CountPassed, $CountSuspicious, $CountWarning, $CountFailed) -ForegroundColor White
    Write-Host ("*" * 80) -ForegroundColor $VerdictColor
    Write-Host ""
    Write-Host $ActionGuidance -ForegroundColor White
    Write-Host ""
}

# ==============================================================================
# 14. XUẤT BÁO CÁO (HTML / JSON / CSV)
# ==============================================================================
$EndTime = Get-Date
$ExecutionDuration = [math]::Round(($EndTime - $StartTime).TotalSeconds, 2)

$InvoiceReportData = if ($MatchedInvoice) {
    [PSCustomObject]@{
        Matched         = $true
        InvoiceNumber   = $MatchedInvoice.InvoiceNumber
        InvoiceSeries   = $MatchedInvoice.InvoiceSeries
        InvoiceDate     = $MatchedInvoice.InvoiceDate
        VendorName      = $MatchedInvoice.VendorName
        VendorTaxId     = $MatchedInvoice.VendorTaxId
        BuyerName       = $MatchedInvoice.BuyerName
        BuyerTaxId      = $MatchedInvoice.BuyerTaxId
        ItemName        = $MatchedInvoice.ItemName
        LicenseEdition  = $MatchedInvoice.LicenseEdition
        MatchReason     = $InvoiceStatusDetails
    }
} else {
    [PSCustomObject]@{
        Matched         = $false
        InvoiceNumber   = "None"
        InvoiceSeries   = "None"
        InvoiceDate     = "None"
        VendorName      = "None"
        BuyerTaxId      = "None"
        MatchReason     = if ($HasOnlyPlaceholders) { "Kho hóa đơn chỉ là dữ liệu mẫu giả định (Placeholder)" } else { "Chưa tìm thấy hóa đơn đối ứng trong hệ thống" }
    }
}

$ReportObject = [PSCustomObject]@{
    ComputerName       = $ComputerName
    HardwareSerial     = $HardwareSerial
    HardwareUUID       = $HardwareUUID
    IsVirtualMachine   = $IsVirtualMachine
    VmPlatform         = $VmPlatform
    CurrentUser        = $CurrentUser
    OSCaption          = $OSCaption
    OSVersion          = $OSVersion
    OSBuild            = $OSBuild
    Manufacturer       = $Manufacturer
    Model              = $Model
    DomainJoined       = $DomainJoined
    DomainName         = $DomainName
    OEMKeyInBios       = $Oa3Key
    LicenseStatus      = $LicenseStatusString
    ProductKeyChannel  = $ProductKeyChannel
    PartialKey         = $PartialKey
    IsGenericKey       = $IsGenericKey
    IsPermanent        = $IsPermanentActivation
    IsKms38Crack       = $IsKms38Crack
    MasTraceFound      = $MasTraceFound
    KmsServer          = $KmsServer
    InvoiceVerified    = $HasInvoicePassed
    InvoiceData        = $InvoiceReportData
    FinalVerdict       = $FinalVerdict
    VerdictTitle       = $VerdictTitle
    CountPassed        = $CountPassed
    CountSuspicious    = $CountSuspicious
    CountWarning       = $CountWarning
    CountFailed        = $CountFailed
    AuditStandard      = "Nghị định 341/2025/NĐ-CP & ISO/IEC 19770"
    AuditDate          = $EndTime.ToString("yyyy-MM-dd HH:mm:ss")
    ExecutionSeconds   = $ExecutionDuration
    DetailedFindings   = $AuditFindings
}

# Xuất JSON
if ($ExportJson) {
    try {
        $jsonDir = [System.IO.Path]::GetDirectoryName($ExportJson)
        if ($jsonDir -and -not (Test-Path $jsonDir)) { New-Item -ItemType Directory -Path $jsonDir -Force | Out-Null }
        $ReportObject | ConvertTo-Json -Depth 5 | Set-Content -Path $ExportJson -Encoding UTF8
        if (-not $Quiet) { Write-Host "  [+] Đã xuất báo cáo JSON: $ExportJson" -ForegroundColor Green }
    } catch {
        Write-Warning "Không thể xuất JSON: $($_.Exception.Message)"
    }
}

# Xuất CSV
if ($ExportCsv) {
    try {
        $csvDir = [System.IO.Path]::GetDirectoryName($ExportCsv)
        if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }
        $csvRow = [PSCustomObject]@{
            ComputerName      = $ComputerName
            HardwareSerial    = $HardwareSerial
            IsVirtualMachine  = if ($IsVirtualMachine) { "YES ($VmPlatform)" } else { "NO" }
            OSCaption         = $OSCaption
            Build             = $OSBuild
            LicenseStatus     = $LicenseStatusString
            Channel           = $ProductKeyChannel
            PartialKey        = $PartialKey
            IsGenericKey      = if ($IsGenericKey) { "YES" } else { "NO" }
            OEMKeyInBios      = $Oa3Key
            MasTraceFound     = if ($MasTraceFound) { "YES" } else { "NO" }
            InvoiceMatched    = if ($HasInvoicePassed) { "YES" } else { "NO" }
            InvoiceNumber     = if ($MatchedInvoice) { $MatchedInvoice.InvoiceNumber } else { "N/A" }
            InvoiceDate       = if ($MatchedInvoice) { $MatchedInvoice.InvoiceDate } else { "N/A" }
            VendorName        = if ($MatchedInvoice) { $MatchedInvoice.VendorName } else { "N/A" }
            BuyerTaxId        = if ($MatchedInvoice) { $MatchedInvoice.BuyerTaxId } else { "N/A" }
            FinalVerdict      = $FinalVerdict
            CountFailed       = $CountFailed
            AuditDate         = $EndTime.ToString("yyyy-MM-dd HH:mm:ss")
        }
        $csvRow | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8 -Append
        if (-not $Quiet) { Write-Host "  [+] Đã xuất/cập nhật file CSV: $ExportCsv" -ForegroundColor Green }
    } catch {
        Write-Warning "Không thể xuất CSV: $($_.Exception.Message)"
    }
}

# Xuất HTML Report chuyên nghiệp
if ($ExportHtml) {
    try {
        $htmlDir = [System.IO.Path]::GetDirectoryName($ExportHtml)
        if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }

        $bannerClass = switch ($FinalVerdict) {
            "GENUINE_COMPLIANT"        { "banner-pass" }
            "SUSPICIOUS_UNVERIFIED"    { "banner-warn" }
            "WARNING_MISSING_INVOICE"  { "banner-warn" }
            "NON_COMPLIANT_UNLICENSED" { "banner-fail" }
            "CRITICAL_PIRATED_CRACKED" { "banner-fail" }
            default                    { "banner-warn" }
        }

        $findingsRowsHtml = ""
        foreach ($f in $AuditFindings) {
            $badgeClass = switch ($f.Status) {
                "PASSED"     { "badge-pass" }
                "SUSPICIOUS" { "badge-susp" }
                "WARNING"    { "badge-warn" }
                "FAILED"     { "badge-fail" }
                default      { "badge-info" }
            }
            $catEsc = [System.Net.WebUtility]::HtmlEncode($f.Category)
            $itemEsc = [System.Net.WebUtility]::HtmlEncode($f.Item)
            $detEsc = [System.Net.WebUtility]::HtmlEncode($f.Details)
            $riskEsc = [System.Net.WebUtility]::HtmlEncode($f.LegalRisk)

            $findingsRowsHtml += @"
            <tr>
                <td>$catEsc</td>
                <td><strong>$itemEsc</strong></td>
                <td><span class="badge $badgeClass">$($f.Status)</span></td>
                <td>$detEsc</td>
                <td>$riskEsc</td>
            </tr>
"@
        }

        $invoiceSectionHtml = if ($MatchedInvoice) {
@"
            <div style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 15px; margin-top: 10px;">
                <div style="font-weight: bold; color: #166534; margin-bottom: 8px;">✔ ĐÃ ĐỐI SOÁT HÓA ĐƠN ĐIỆN TỬ VAT HỢP LỆ (Khớp: $InvoiceStatusDetails)</div>
                <div class="grid" style="margin-bottom: 0;">
                    <div class="card"><div class="title">Số Hóa Đơn</div><div class="value">$($MatchedInvoice.InvoiceNumber)</div></div>
                    <div class="card"><div class="title">Ký Hiệu / Mẫu Số</div><div class="value">$($MatchedInvoice.InvoiceSeries)</div></div>
                    <div class="card"><div class="title">Ngày Lập HĐ</div><div class="value">$($MatchedInvoice.InvoiceDate)</div></div>
                    <div class="card"><div class="title">Đơn Vị Cung Cấp</div><div class="value">$($MatchedInvoice.VendorName)</div></div>
                    <div class="card"><div class="title">Đơn Vị Mua Hàng</div><div class="value">$($MatchedInvoice.BuyerName)</div></div>
                    <div class="card"><div class="title">Mã Số Thuế Bên Mua</div><div class="value">$($MatchedInvoice.BuyerTaxId)</div></div>
                    <div class="card"><div class="title">Nội Dung Hàng Hóa</div><div class="value">$($MatchedInvoice.ItemName)</div></div>
                </div>
            </div>
"@
        } else {
            $msgTitle = if ($HasOnlyPlaceholders) { "TỆP HÓA ĐƠN CHỈ LÀ DỮ LIỆU MẪU MẶC ĐỊNH (PLACEHOLDER)" } else { "CHƯA LIÊN KẾT ĐƯỢC HÓA ĐƠN GTGT ĐỐI ỨNG" }
            $msgDesc = if ($HasOnlyPlaceholders) {
                "Tệp hóa đơn hiện tại trong thư mục (<strong>$ResolvedInvoiceFile</strong>) là dữ liệu mẫu giả định của dự án ('CÔNG TY DOANH NGHIỆP CỦA BẠN'). Doanh nghiệp cần cập nhật thông tin Hóa đơn điện tử VAT thật trước khi chạy đối soát chính thức."
            } else {
                "Không tìm thấy bản ghi hóa đơn mua hàng khớp với Serial máy (<strong>$HardwareSerial</strong>) hoặc Hostname trong kho dữ liệu chứng từ. Đề nghị kế toán bổ sung vào hồ sơ lưu trữ để xuất trình khi thanh tra."
            }

@"
            <div style="background: #fefce8; border: 1px solid #fef08a; border-radius: 6px; padding: 15px; margin-top: 10px; color: #854d0e;">
                <strong>⚠ ${msgTitle}:</strong> $msgDesc
            </div>
"@
        }

        $htmlTemplate = @"
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Báo Cáo Kiểm Toán Bản Quyền Windows - $ComputerName</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f4f6f9; margin: 0; padding: 20px; color: #333; }
        .container { max-width: 1100px; margin: 0 auto; background: #fff; border-radius: 8px; box-shadow: 0 4px 16px rgba(0,0,0,0.08); overflow: hidden; }
        .header { background: #0f172a; color: #fff; padding: 24px 30px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; font-size: 22px; }
        .header .meta { font-size: 13px; color: #94a3b8; }
        .banner { padding: 20px 30px; font-size: 18px; font-weight: bold; text-align: center; }
        .banner-pass { background-color: #dcfce7; color: #166534; border-bottom: 2px solid #86efac; }
        .banner-warn { background-color: #fef9c3; color: #854d0e; border-bottom: 2px solid #fde047; }
        .banner-fail { background-color: #fee2e2; color: #991b1b; border-bottom: 2px solid #fca5a5; }
        .content { padding: 30px; }
        h2 { font-size: 16px; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; margin-top: 24px; color: #0f172a; text-transform: uppercase; letter-spacing: 0.5px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 16px; }
        .card .title { font-size: 12px; color: #64748b; margin-bottom: 4px; text-transform: uppercase; }
        .card .value { font-size: 15px; font-weight: 600; color: #0f172a; word-break: break-word; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
        th { background: #f1f5f9; color: #475569; font-weight: 600; }
        tr:hover { background-color: #f8fafc; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }
        .badge-pass { background: #dcfce7; color: #15803d; }
        .badge-susp { background: #fef3c7; color: #b45309; }
        .badge-warn { background: #fae8ff; color: #86198f; }
        .badge-fail { background: #fee2e2; color: #b91c1c; }
        .badge-info { background: #e0f2fe; color: #0369a1; }
        .guidance-box { background: #fffbeb; border-left: 4px solid #f59e0b; padding: 15px 20px; border-radius: 4px; margin-top: 20px; font-size: 13px; line-height: 1.6; white-space: pre-wrap; font-family: inherit; }
        .footer { background: #f8fafc; border-top: 1px solid #e2e8f0; padding: 15px 30px; font-size: 12px; color: #94a3b8; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>BÁO CÁO KIỂM TOÁN TÍNH TUÂN THỦ BẢN QUYỀN WINDOWS</h1>
                <div class="meta">Thiết bị: $ComputerName | Serial: $HardwareSerial | Người dùng: $CurrentUser | Ngày: $($ReportObject.AuditDate)</div>
            </div>
            <div>
                <span style="font-size: 12px; background: #334155; padding: 6px 12px; border-radius: 4px;">Tiêu chuẩn: NĐ 341/2025/NĐ-CP</span>
            </div>
        </div>

        <div class="banner $bannerClass">
            $VerdictTitle
        </div>

        <div class="content">
            <h2>1. Tổng Quan Giấy Phép & Định Danh Thiết Bị</h2>
            <div class="grid">
                <div class="card"><div class="title">Tên thiết bị (Hostname)</div><div class="value">$ComputerName</div></div>
                <div class="card"><div class="title">Số Serial / Service Tag</div><div class="value">$HardwareSerial</div></div>
                <div class="card"><div class="title">Loại phần cứng</div><div class="value">$(if ($IsVirtualMachine) { "Máy ảo ($VmPlatform)" } else { "Máy tính vật lý (Physical)" })</div></div>
                <div class="card"><div class="title">Hệ điều hành</div><div class="value">$OSCaption</div></div>
                <div class="card"><div class="title">Trạng thái bản quyền</div><div class="value">$LicenseStatusString</div></div>
                <div class="card"><div class="title">Kênh bản quyền (Channel)</div><div class="value">$ProductKeyChannel</div></div>
                <div class="card"><div class="title">5 Ký tự cuối Key</div><div class="value">$PartialKey $(if ($IsGenericKey) { "<span style='color:#dc2626; font-size:11px;'>(Generic Key)</span>" } else { "" })</div></div>
                <div class="card"><div class="title">OEM Key trong BIOS</div><div class="value">$(if ($Oa3Key) { $Oa3Key } else { "Không có" })</div></div>
                <div class="card"><div class="title">Kích hoạt vĩnh viễn</div><div class="value">$(if ($IsKms38Crack) { "KMS38 (Crack đến 2038)" } elseif ($IsPermanentActivation) { "Vĩnh viễn (Permanent)" } else { "Có thời hạn (KMS/Grace)" })</div></div>
                <div class="card"><div class="title">Dấu vết bẻ khóa MAS</div><div class="value">$(if ($MasTraceFound) { "<span style='color:#dc2626;'>PHÁT HIỆN DẤU VẾT</span>" } else { "<span style='color:#16a34a;'>Sạch</span>" })</div></div>
            </div>

            <h2>2. Chứng Từ Hóa Đơn Điện Tử VAT Đối Ứng (Nghị định 341/2025/NĐ-CP)</h2>
            $invoiceSectionHtml

            <h2>3. Hướng Dẫn & Đánh Giá Rủi Ro Pháp Lý</h2>
            <div class="guidance-box">$ActionGuidance</div>

            <h2>4. Chi Tiết Rà Soát Kỹ Thuật (Authenticode, MAS Forensics, Registry, KMS, HackTools, Tasks, Hosts)</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 15%;">Hạng mục</th>
                        <th style="width: 20%;">Đối tượng kiểm tra</th>
                        <th style="width: 10%;">Trạng thái</th>
                        <th style="width: 35%;">Chi tiết phát hiện kỹ thuật</th>
                        <th style="width: 20%;">Đánh giá rủi ro pháp lý</th>
                    </tr>
                </thead>
                <tbody>
                    $findingsRowsHtml
                </tbody>
            </table>
        </div>

        <div class="footer">
            Báo cáo được khởi tạo tự động bởi công cụ Audit-WindowsLicenseCompliance (Enterprise Forge Security Tool).<br>
            Dữ liệu có giá trị phục vụ công tác rà soát nội bộ và chuẩn bị hồ sơ thanh kiểm tra theo quy định pháp luật.
        </div>
    </div>
</body>
</html>
"@
        $htmlTemplate | Set-Content -Path $ExportHtml -Encoding UTF8
        if (-not $Quiet) { Write-Host "  [+] Đã xuất báo cáo HTML: $ExportHtml" -ForegroundColor Green }
    } catch {
        Write-Warning "Không thể xuất HTML: $($_.Exception.Message)"
    }
}

$global:LASTEXITCODE = $ExitCode
exit $ExitCode
