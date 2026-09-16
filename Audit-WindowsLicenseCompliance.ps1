<#
.SYNOPSIS
    Audit-WindowsLicenseCompliance.ps1 - Enterprise Windows License & Piracy Audit Tool
    Phần mềm Kiểm tra Bản quyền Windows, Phát hiện Công cụ Bẻ khóa & Đối soát Hóa đơn VAT Doanh nghiệp.
    Phát triển bởi: @uziii2208. Bản quyền MIT License @2026

.DESCRIPTION
    Script chuyên dụng dành cho Quản trị viên IT, Bộ phận Pháp chế, Kế toán & An toàn thông tin Doanh nghiệp
    nhằm rà soát toàn diện tính tuân thủ bản quyền Windows, phục vụ công tác thanh kiểm tra của cơ quan chức năng
    theo Nghị định 341/2025/NĐ-CP (quy định xử phạt vi phạm hành chính trong lĩnh vực sở hữu trí tuệ, quyền tác giả,
    an toàn thông tin mạng và sử dụng phần mềm máy tính), Nghị định 131/2013/NĐ-CP, Nghị định 14/2022/NĐ-CP,
    và Điều 225 Bộ luật Hình sự.

    Các module rà soát chuyên sâu:
    1. Trạng thái bản quyền chính thức qua Software Protection Platform (WMI/CIM/slmgr).
    2. Nhận diện Kênh bản quyền (Retail, OEM:DM, Volume:MAK, Volume:GVLK/KMS).
    3. Trích xuất OEM Factory Key nguyên bản từ bo mạch chủ UEFI/BIOS ACPI MSDM & Serial Number phần cứng.
    4. Kiểm tra Chữ ký số Authenticode & Tính toàn vẹn của các file hệ thống (sppc.dll, sppsvc.exe, slmgr.vbs).
    5. Phát hiện cơ chế bẻ khóa tinh vi Ohook / MAS (Microsoft Activation Scripts) qua sppcs.dll & sppc.dll hook.
    6. Phát hiện SppExtComObjHook, IFEO Debugger Hijacking cho tiến trình bản quyền.
    7. Nhận diện máy chủ KMS lậu (Localhost emulator 127.0.0.1 hoặc Public Internet KMS servers).
    8. Quét dấu vết các bộ công cụ bẻ khóa: KMSpico, AutoKMS, KMSAuto Net, AAct, Microsoft Toolkit, HEU KMS.
    9. Quét tác vụ đặt lịch tự động re-arm / re-activate (Scheduled Tasks).
    10. Kiểm tra danh sách loại trừ bất thường của Windows Defender (Defender Exclusions).
    11. Kiểm tra can thiệp file HOSTS chuyển hướng máy chủ kích hoạt Microsoft.
    12. ĐỐI SOÁT HÓA ĐƠN ĐIỆN TỬ VAT THỰC TẾ: Tự động kết nối REST API hoặc đọc File cơ sở dữ liệu hóa đơn
        (invoices.json / invoices.csv / XML TCT) để so khớp Serial máy, Hostname, Product Key, Phiên bản Windows
        và Mã số thuế doanh nghiệp (Nghĩa vụ chứng minh nguồn gốc theo NĐ 341/2025/NĐ-CP).
    13. Đánh giá rủi ro pháp lý & Xuất báo cáo đa định dạng (Console, HTML chuyên nghiệp, JSON, CSV).

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
    1 = SUSPICIOUS (Cần bổ sung/xác minh hóa đơn VAT hoặc hợp đồng Volume Licensing)
    2 = NON-COMPLIANT (Chưa kích hoạt hoặc đã hết hạn dùng thử)
    3 = CRITICAL_PIRATED (Phát hiện dấu vết bẻ khóa, crack, rogue KMS, can thiệp file hệ thống)
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

# ==============================================================================
# 1. THÔNG TIN THIẾT BỊ & HỆ ĐIỀU HÀNH
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
$Manufacturer   = $CompSystem.Manufacturer
$Model          = $CompSystem.Model
$DomainJoined   = $CompSystem.PartOfDomain
$DomainName     = $CompSystem.Domain
$HardwareSerial = if ($BiosInfo.SerialNumber) { $BiosInfo.SerialNumber.Trim() } else { "Unknown" }
$HardwareUUID   = if ($CsProduct.UUID) { $CsProduct.UUID.Trim() } else { "Unknown" }

Write-ResultItem "Tên máy tính (Hostname)" $ComputerName "INFO"
Write-ResultItem "Số Serial phần cứng (Service Tag)" $HardwareSerial "INFO"
Write-ResultItem "Người dùng hiện tại" $CurrentUser "INFO"
Write-ResultItem "Nhà sản xuất / Model" "$Manufacturer $Model" "INFO"
Write-ResultItem "Phiên bản Windows" "$OSCaption (Build $OSBuild, $OSArch)" "INFO"
Write-ResultItem "Gia nhập Domain (AD)" $(if ($DomainJoined) { "Có ($DomainName)" } else { "Không (Workgroup)" }) "INFO"
Write-ResultItem "Quyền thực thi Script" $(if ($IsAdmin) { "Administrator (Toàn quyền rà soát)" } else { "Standard User (Khuyến nghị chạy Run as Admin để quét sâu Defender)" }) $(if ($IsAdmin) { "PASSED" } else { "SUSPICIOUS" })

# Kiểm tra OEM Factory License trong BIOS/UEFI (ACPI MSDM table)
$Oa3Key = ""
try {
    $sppService = Get-CimInstance -ClassName SoftwareLicensingService
    if ($sppService.OA3xOriginalProductKey) {
        $Oa3Key = $sppService.OA3xOriginalProductKey
    }
} catch {}

if ($Oa3Key) {
    Write-ResultItem "OEM Key trong BIOS (MSDM)" "$Oa3Key (Bản quyền gốc đi theo phần cứng máy)" "PASSED"
    Add-Finding "Hardware License" "BIOS MSDM Key" "PASSED" "Máy tính có sẵn key bản quyền OEM nhúng trong bo mạch chủ từ nhà sản xuất ($Oa3Key)." "Hợp lệ về phần cứng"
} else {
    Write-ResultItem "OEM Key trong BIOS (MSDM)" "Không phát hiện (Máy lắp ráp, máy ảo hoặc bo mạch chủ không nhúng key OEM)" "INFO"
    Add-Finding "Hardware License" "BIOS MSDM Key" "INFO" "Không có key OEM trong BIOS. Cần có giấy phép Retail/FPP hoặc Volume Licensing." "Cần chứng từ kèm theo"
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
    $PartialKey = $WinProduct.PartialProductKey
    $ProductDescription = $WinProduct.Description
    $ProductKeyChannel = $WinProduct.ProductKeyChannel
    $KmsMachineConfigured = $WinProduct.KeyManagementServiceMachine
    $KmsMachineDiscovered = $WinProduct.DiscoveredKeyManagementServiceMachineName
    if ($WinProduct.GracePeriodRemaining) {
        $GracePeriodDays = [math]::Round($WinProduct.GracePeriodRemaining / 1440, 1)
    }

    switch ($LicenseStatusCode) {
        0 { $LicenseStatusString = "Unlicensed (Chưa có giấy phép)" }
        1 { $LicenseStatusString = "Licensed (Đã kích hoạt hợp lệ)" }
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

Write-ResultItem "Trạng thái Giấy phép" $LicenseStatusString $(if ($LicenseStatusCode -eq 1) { "PASSED" } else { "FAILED" })
Write-ResultItem "Kênh cấp phép (Channel)" $ProductKeyChannel $(if ($ProductKeyChannel -match "Retail|OEM") { "PASSED" } else { "SUSPICIOUS" })
Write-ResultItem "5 ký tự cuối Product Key" $PartialKey "INFO"
Write-ResultItem "Mô tả sản phẩm" $ProductDescription "INFO"
Write-ResultItem "Thời hạn kích hoạt (slmgr /xpr)" $(if ($SlmgrXprOutput) { $SlmgrXprOutput.Replace("`r`n", " - ") } else { "Không truy xuất được" }) $(if ($IsPermanentActivation) { "PASSED" } else { "SUSPICIOUS" })

if ($LicenseStatusCode -eq 1) {
    if ($ProductKeyChannel -match "OEM") {
        Add-Finding "License Channel" "Kênh OEM" "PASSED" "Windows kích hoạt theo bản quyền OEM kèm máy tính." "Tuân thủ hợp pháp nếu mua kèm máy"
    } elseif ($ProductKeyChannel -match "Retail") {
        Add-Finding "License Channel" "Kênh Retail" "PASSED" "Windows kích hoạt theo bản quyền bán lẻ Retail/FPP." "Hợp pháp nếu có hóa đơn/license hợp lệ"
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
    "kms.mindfly.cn", "kms.landiannews.com", "kms.ghpym.com"
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

# ==============================================================================
# 4. KIỂM TRA CHỮ KÝ SỐ FILE HỆ THỐNG & KỸ THUẬT BẺ KHÓA OHOOK (MAS)
# ==============================================================================
Write-Section "4. KIỂM TRA CHỮ KÝ SỐ FILE HỆ THỐNG & KỸ THUẬT BẺ KHÓA OHOOK (MAS)"

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
    Add-Finding "Ohook Mas Detection" "Ohook MAS Artifacts" "PASSED" "Không phát hiện tệp hoặc cơ chế can thiệp Ohook." "Bình thường"
}

# ==============================================================================
# 5. PHÁT HIỆN SppExtComObjHook & CÁC TỆP TIN DLL BẺ KHÓA
# ==============================================================================
Write-Section "5. RÀ SOÁT TỆP HOOK TIẾN TRÌNH (SppExtComObjHook)"

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
# 6. PHÁT HIỆN CAN THIỆP REGISTRY & IFEO DEBUGGER HIJACKING
# ==============================================================================
Write-Section "6. RÀ SOÁT REGISTRY CAN THIỆP & IFEO DEBUGGER HIJACKING"

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

$SuspiciousServices = @("KMSEmulator", "AutoKMS", "KMSAuto", "KmsService", "Service_KMS")
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
# 7. QUÉT THƯ MỤC & CÔNG CỤ BẺ KHÓA TRÊN ĐĨA CỨNG
# ==============================================================================
Write-Section "7. QUÉT CÔNG CỤ & TỆP TIN BẺ KHÓA (KMSpico, AutoKMS, KMSAuto, MAS...)"

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
    "$env:windir\Setup\Scripts\SetupComplete.cmd",
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
# 8. QUÉT TÁC VỤ ĐẶT LỊCH (SCHEDULED TASKS) DUY TRÌ BẢN QUYỀN LẬU
# ==============================================================================
Write-Section "8. RÀ SOÁT TÁC VỤ LÊN LỊCH TỰ ĐỘNG RE-ARM (SCHEDULED TASKS)"

$SuspiciousTaskPatterns = @("AutoKMS", "KMSpico", "KMSAuto", "AAct", "AutoPico")
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
# 9. KIỂM TRA DANH SÁCH LOẠI TRỪ CỦA WINDOWS DEFENDER (DEFENDER EXCLUSIONS)
# ==============================================================================
Write-Section "9. KIỂM TRA LOẠI TRỪ CỦA WINDOWS DEFENDER (DEFENDER TAMPERING)"

if ($IsAdmin) {
    try {
        $mpPref = Get-MpPreference -ErrorAction Stop
        $exclPaths = $mpPref.ExclusionPath
        $exclProcs = $mpPref.ExclusionProcess

        $DefenderTampered = $false
        $CrackPatterns = @("AutoKMS", "KMSpico", "KMSAuto", "AAct", "SppExtComObj", "MAS", "Activator")

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
# 10. KIỂM TRA CAN THIỆP FILE HOSTS (CHUYỂN HƯỚNG MÁY CHỦ BẢN QUYỀN)
# ==============================================================================
Write-Section "10. RÀ SOÁT TỆP TIN HOSTS (CHUYỂN HƯỚNG MÁY CHỦ MICROSOFT)"

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
# 11. ĐỐI SOÁT HÓA ĐƠN ĐIỆN TỬ VAT THỰC TẾ (INVOICE PROCUREMENT AUDIT)
# ==============================================================================
Write-Section "11. ĐỐI SOÁT HÓA ĐƠN ĐIỆN TỬ VAT THỰC TẾ (NGHỊ ĐỊNH 341/2025/NĐ-CP)"

$MatchedInvoice = $null
$InvoiceStatus = "NOT_CHECKED"
$InvoiceStatusDetails = ""
$InvoiceDatabase = [System.Collections.Generic.List[PSObject]]::new()

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
        Write-ResultItem "Kho Hóa đơn (File)" "Đã nạp thành công $($InvoiceDatabase.Count) chứng từ hóa đơn" "PASSED"
    } catch {
        Write-ResultItem "Kho Hóa đơn (File)" "Lỗi đọc tệp hóa đơn: $($_.Exception.Message)" "WARNING"
    }
}

# Tiến hành đối soát máy tính hiện tại với cơ sở dữ liệu hóa đơn (Ưu tiên khớp chính xác thiết bị trước, sau đó mới tới gói pool tập trung)
if ($InvoiceDatabase.Count -gt 0) {
    # Vòng 1: Tìm hóa đơn khớp trực tiếp phần cứng / thiết bị
    foreach ($inv in $InvoiceDatabase) {
        if ($inv.TargetIdentifier -and $HardwareSerial -ne "Unknown" -and ($inv.TargetIdentifier.ToString().Trim().ToUpper() -eq $HardwareSerial.ToUpper())) {
            $MatchedInvoice = $inv
            $InvoiceStatusDetails = "Khớp chính xác Service Tag/Serial phần cứng máy: $HardwareSerial"
            break
        }
        elseif ($inv.TargetIdentifier -and ($inv.TargetIdentifier.ToString().Trim().ToUpper() -eq $ComputerName.ToUpper())) {
            $MatchedInvoice = $inv
            $InvoiceStatusDetails = "Khớp chính xác Tên máy tính (Hostname): $ComputerName"
            break
        }
        elseif ($inv.TargetKey -and (($Oa3Key -and $inv.TargetKey -like "*$Oa3Key*") -or ($PartialKey -ne "None" -and $inv.TargetKey -like "*$PartialKey*"))) {
            $MatchedInvoice = $inv
            $InvoiceStatusDetails = "Khớp khóa bản quyền phần cứng: $(if ($Oa3Key) { $Oa3Key } else { $PartialKey })"
            break
        }
    }

    # Vòng 2: Nếu chưa có hóa đơn riêng lẻ, tìm hóa đơn gói bản quyền tập trung doanh nghiệp (Enterprise Pool)
    if (-not $MatchedInvoice) {
        foreach ($inv in $InvoiceDatabase) {
            if ($inv.TargetIdentifier -and ($inv.TargetIdentifier.ToString().ToUpper() -eq "ALL_ENTERPRISE_POOL")) {
                $MatchedInvoice = $inv
                $InvoiceStatusDetails = "Nằm trong Hợp đồng/Hóa đơn mua gói bản quyền tập trung toàn doanh nghiệp"
                break
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

    # Kiểm tra tính tương thích phiên bản (Ví dụ: Máy cài Pro nhưng hóa đơn chỉ mua Home)
    $EditionMismatch = $false
    if ($OSCaption -like "*Pro*" -and $invEdition -and $invEdition -like "*Home*") {
        $EditionMismatch = $true
    }

    # Kiểm tra Mã số thuế Doanh nghiệp nếu được chỉ định
    $TaxIdMismatch = $false
    if ($ExpectedTaxId -and $invBuyerTaxId -and ($invBuyerTaxId.Trim() -ne $ExpectedTaxId.Trim())) {
        $TaxIdMismatch = $true
    }

    if ($EditionMismatch) {
        Write-ResultItem "Xác thực Hóa đơn" "LỆCH PHIÊN BẢN: Máy chạy Windows Pro nhưng hóa đơn chỉ mua Windows Home!" "FAILED"
        Add-Finding "Invoice Audit" "Edition Mismatch" "FAILED" "Thiết bị đang cài Windows Pro nhưng hóa đơn số $invNum chỉ cấp phép bản Home. Đây là lỗi vi phạm bản quyền rất phổ biến bị phạt nặng khi thanh tra theo NĐ 341/2025/NĐ-CP." "Vi phạm bản quyền do nâng cấp trái phép"
    } elseif ($TaxIdMismatch) {
        Write-ResultItem "Xác thực Hóa đơn" "MÃ SỐ THUẾ KHÔNG KHỚP: MST trên hóa đơn ($invBuyerTaxId) khác MST doanh nghiệp ($ExpectedTaxId)!" "WARNING"
        Add-Finding "Invoice Audit" "Tax ID Mismatch" "WARNING" "Hóa đơn số $invNum đứng tên MST khác ($invBuyerTaxId). Không chứng minh được tài sản thuộc quyền sở hữu của doanh nghiệp bạn." "Nguy cơ bị loại trừ chứng từ hợp lệ"
    } else {
        Write-ResultItem "Xác thực Hóa đơn" "HỢP LỆ VÀ ĐẦY ĐỦ PHÁP LÝ (Khớp: $InvoiceStatusDetails)" "PASSED"
        Add-Finding "Invoice Audit" "VAT Invoice Verified" "PASSED" "Đã đối soát thành công Hóa đơn điện tử VAT Số: $invNum, Ký hiệu: $invSeries, Ngày: $invDate từ nhà cung cấp $invVendor. Đạt chuẩn chứng từ theo Nghị định 341/2025/NĐ-CP." "Đầy đủ chứng từ pháp lý xuất trình thanh tra"
    }
} else {
    Write-ResultItem "Đối soát Hóa đơn VAT" "CHƯA TÌM THẤY HÓA ĐƠN ĐỐI ỨNG TRONG KHO DỮ LIỆU" $(if ($RequireInvoice) { "WARNING" } else { "SUSPICIOUS" })
    Add-Finding "Invoice Audit" "Missing VAT Invoice" $(if ($RequireInvoice) { "WARNING" } else { "SUSPICIOUS" }) "Chưa tìm thấy hóa đơn GTGT hoặc hợp đồng cấp phép mua sắm phần mềm tương ứng với thiết bị này (Serial: $HardwareSerial, Hostname: $ComputerName)." "Theo Nghị định 341/2025/NĐ-CP, việc không xuất trình được hóa đơn tài chính hợp pháp khi thanh tra sẽ bị xử phạt vi phạm hành chính"
}

# ==============================================================================
# 12. TỔNG HỢP ĐÁNH GIÁ PHÁP LÝ & KẾT LUẬN TUÂN THỦ (NGHỊ ĐỊNH 341/2025/NĐ-CP)
# ==============================================================================
Write-Section "12. KẾT LUẬN TUÂN THỦ & ĐÁNH GIÁ RỦI RO PHÁP LÝ DOANH NGHIỆP"

$CountFailed = @($AuditFindings | Where-Object { $_.Status -eq "FAILED" }).Count
$CountWarning = @($AuditFindings | Where-Object { $_.Status -eq "WARNING" }).Count
$CountSuspicious = @($AuditFindings | Where-Object { $_.Status -eq "SUSPICIOUS" }).Count
$CountPassed = @($AuditFindings | Where-Object { $_.Status -eq "PASSED" }).Count

# Đếm các lỗi nghi vấn kỹ thuật (loại trừ trường hợp chỉ thiếu quyền Admin quét Defender)
$TechSuspicious = @($AuditFindings | Where-Object { $_.Status -in @("SUSPICIOUS", "WARNING") -and $_.Category -ne "Defender Exclusions" -and $_.Category -ne "Script Execution" -and $_.Category -ne "Invoice Audit" }).Count
$HasInvoicePassed = ($MatchedInvoice -ne $null -and @($AuditFindings | Where-Object { $_.Item -eq "VAT Invoice Verified" -and $_.Status -eq "PASSED" }).Count -gt 0)

$FinalVerdict = "GENUINE_COMPLIANT"
$VerdictTitle = "ĐẠT CHUẨN TUÂN THỦ (GENUINE / COMPLIANT)"
$VerdictColor = "Green"
$ExitCode = 0
$ActionGuidance = ""

if ($CountFailed -gt 0) {
    $FinalVerdict = "CRITICAL_PIRATED_CRACKED"
    $VerdictTitle = "NGUY CƠ CAO: PHÁT HIỆN SỬ DỤNG WINDOWS LẬU / CÔNG CỤ BẺ KHÓA"
    $VerdictColor = "Red"
    $ExitCode = 3
    $ActionGuidance = @"
[CẢNH BÁO PHÁP LÝ CHO DOANH NGHIỆP THEO NGHỊ ĐỊNH 341/2025/NĐ-CP]:
1. Máy tính này đang chứa các công cụ bẻ khóa, file hệ thống bị vá (Ohook/KMS Hook) hoặc máy chủ kích hoạt lậu.
2. Khi cơ quan Thanh tra liên ngành kiểm tra, doanh nghiệp sẽ bị lập biên bản xử phạt vi phạm hành chính về quyền tác giả,
   mức phạt đối với pháp nhân có thể lên đến hàng trăm triệu đồng, đồng thời bị buộc tiêu hủy bản sao lậu và công khai xin lỗi.
3. HÀNH ĐỘNG KHẮC PHỤC NGAY:
   - Gỡ bỏ hoàn toàn các công cụ crack, xóa các Scheduled Task và Defender Exclusions đã phát hiện.
   - Chạy lệnh 'sfc /scannow' và 'dism /online /cleanup-image /restorehealth' với quyền Admin để khôi phục sppc.dll gốc của Microsoft.
   - Nếu máy có OEM Key trong BIOS (MSDM: $Oa3Key): Dùng lệnh 'slmgr.vbs /ipk $Oa3Key' và 'slmgr.vbs /ato' để kích hoạt bản quyền gốc hợp pháp.
   - Nếu không có key OEM: Tiến hành mua giấy phép bản quyền Windows Pro chính hãng (Microsoft CSP / ESD) có đầy đủ Hóa đơn GTGT (VAT).
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
   - Bộ phận Kế toán & IT rà soát lại hóa đơn mua máy tính (có kèm OEM Windows) hoặc hóa đơn mua gói phần mềm ESD/CSP
     và cập nhật số hóa đơn vào file 'invoices.json' / 'invoices.csv' của công ty để hoàn thiện hồ sơ thanh tra.
"@
} elseif ($TechSuspicious -gt 0) {
    $FinalVerdict = "SUSPICIOUS_UNVERIFIED"
    $VerdictTitle = "CẦN XÁC MINH: CẦN ĐỐI SOÁT HÓA ĐƠN / HỢP ĐỒNG BẢN QUYỀN"
    $VerdictColor = "Yellow"
    $ExitCode = 1
    $ActionGuidance = @"
[LƯU Ý ĐỐI SOÁT CHỨNG TỪ DOANH NGHIỆP]:
1. Hệ thống đang báo đã kích hoạt, tuy nhiên đang sử dụng kênh cấp phép Volume License (KMS/MAK) hoặc có dấu hiệu cài đặt lại.
2. Về mặt pháp lý: Thanh tra bản quyền KHÔNG CHỈ nhìn vào màn hình 'Windows is activated' mà BẮT BUỘC kiểm tra:
   - Hóa đơn tài chính (Hóa đơn điện tử VAT) chứng minh việc mua bản quyền.
   - Hợp đồng thỏa thuận cấp phép số lượng lớn (Volume Licensing / Enterprise Agreement / CSP) giữa công ty và Microsoft/Đối tác ủy quyền.
3. HÀNH ĐỘNG KHẮC PHỤC:
   - Bộ phận IT phối hợp cùng Kế toán kiểm tra lại hồ sơ chứng từ lưu trữ của thiết bị này để đảm bảo sẵn sàng khi có thanh kiểm tra.
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
    $ActionGuidance = @"
[ĐÁNH GIÁ PHÁP LÝ THEO NGHỊ ĐỊNH 341/2025/NĐ-CP]:
1. Hệ điều hành đã kích hoạt hợp pháp qua kênh chính thức ($ProductKeyChannel), các file hệ thống và chữ ký số nguyên bản của Microsoft.
2. Không phát hiện bất kỳ dấu vết công cụ bẻ khóa, DLL Hook, máy chủ KMS lạ hay tác vụ can thiệp ngầm.
$(if ($HasInvoicePassed) {
"3. [XÁC THỰC THÀNH CÔNG]: Thiết bị đã được liên kết với Hóa đơn điện tử VAT hợp lệ (Số: $($MatchedInvoice.InvoiceNumber), Ngày: $($MatchedInvoice.InvoiceDate) của $($MatchedInvoice.VendorName)). ĐẦY ĐỦ HỒ SƠ PHÁP LÝ ĐỂ XUẤT TRÌNH THANH TRA."
} else {
"3. [LƯU Ý CHỨNG TỪ]: Doanh nghiệp cần đảm bảo lưu giữ Hóa đơn VAT / Thỏa thuận mua bản quyền tương ứng với thiết bị này (Serial: $HardwareSerial) trong hồ sơ kế toán."
})
"@
}

if (-not $Quiet) {
    Write-Host ""
    Write-Host ("*" * 80) -ForegroundColor $VerdictColor
    Write-Host "  KẾT QUẢ CUỐI CÙNG : $VerdictTitle" -ForegroundColor $VerdictColor
    Write-Host "  MÃ ĐÁNH GIÁ       : $FinalVerdict" -ForegroundColor White
    Write-Host ("  TỔNG HỢP CHỈ SỐ   : {0} Đạt | {1} Cần xác minh | {2} Cảnh báo | {3} Vi phạm nghiêm trọng" -f $CountPassed, $CountSuspicious, $CountWarning, $CountFailed) -ForegroundColor White
    Write-Host ("*" * 80) -ForegroundColor $VerdictColor
    Write-Host ""
    Write-Host $ActionGuidance -ForegroundColor White
    Write-Host ""
}

# ==============================================================================
# 13. XUẤT BÁO CÁO (HTML / JSON / CSV)
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
        MatchReason     = "Chưa tìm thấy hóa đơn đối ứng trong hệ thống"
    }
}

$ReportObject = [PSCustomObject]@{
    ComputerName       = $ComputerName
    HardwareSerial     = $HardwareSerial
    HardwareUUID       = $HardwareUUID
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
    IsPermanent        = $IsPermanentActivation
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
            OSCaption         = $OSCaption
            Build             = $OSBuild
            LicenseStatus     = $LicenseStatusString
            Channel           = $ProductKeyChannel
            PartialKey        = $PartialKey
            OEMKeyInBios      = $Oa3Key
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
            @"
            <div style="background: #fefce8; border: 1px solid #fef08a; border-radius: 6px; padding: 15px; margin-top: 10px; color: #854d0e;">
                <strong>⚠ CHƯA LIÊN KẾT ĐƯỢC HÓA ĐƠN GTGT ĐỐI ỨNG:</strong> Không tìm thấy bản ghi hóa đơn mua hàng khớp với Serial máy (<strong>$HardwareSerial</strong>) hoặc Hostname trong kho dữ liệu chứng từ. Đề nghị kế toán bổ sung vào hồ sơ lưu trữ để xuất trình khi thanh tra.
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
                <div class="card"><div class="title">Hệ điều hành</div><div class="value">$OSCaption</div></div>
                <div class="card"><div class="title">Trạng thái bản quyền</div><div class="value">$LicenseStatusString</div></div>
                <div class="card"><div class="title">Kênh bản quyền (Channel)</div><div class="value">$ProductKeyChannel</div></div>
                <div class="card"><div class="title">5 Ký tự cuối Key</div><div class="value">$PartialKey</div></div>
                <div class="card"><div class="title">OEM Key trong BIOS</div><div class="value">$(if ($Oa3Key) { $Oa3Key } else { "Không có" })</div></div>
                <div class="card"><div class="title">Kích hoạt vĩnh viễn</div><div class="value">$(if ($IsPermanentActivation) { "Vĩnh viễn (Permanent)" } else { "Có thời hạn (KMS/Grace)" })</div></div>
            </div>

            <h2>2. Chứng Từ Hóa Đơn Điện Tử VAT Đối Ứng (Nghị định 341/2025/NĐ-CP)</h2>
            $invoiceSectionHtml

            <h2>3. Hướng Dẫn & Đánh Giá Rủi Ro Pháp Lý</h2>
            <div class="guidance-box">$ActionGuidance</div>

            <h2>4. Chi Tiết Rà Soát Kỹ Thuật (Authenticode, Registry, KMS, HackTools, Tasks, Hosts)</h2>
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

exit $ExitCode
