clear-host

# Output folder and log file setup
$resultsPath = "C:\ss5"
$logFile = "DMA_Info.txt"
$logFilePath = Join-Path $resultsPath $logFile

# Check if C:\ss5 folder exists
if (-not (Test-Path $resultsPath)) {
    # Creating C:\ss5 if it doesn't exist
    Write-Host "Creating C:\ss5 folder..." -ForegroundColor Green
    New-Item -Path $resultsPath -ItemType Directory -Force | Out-Null
} else {
    # If it exists, clear the directory without logging
    Write-Host "Clearing C:\ss5 folder..." -ForegroundColor Green
    Remove-Item -Path "$resultsPath\*" -Recurse -Force | Out-Null
}

# Function to fetch device data from DeviceHunt API for validation based on device type
function Get-DeviceFromDeviceHunt {
    param (
        [string]$vendorId,
        [string]$productId,
        [string]$deviceType
    )

    # Construct the appropriate DeviceHunt URL based on the device type (USB or PCI)
    $url = if ($deviceType -eq "USB") {
        "https://devicehunt.com/search/type/usb/vendor/$vendorId/device/$productId"
    } elseif ($deviceType -eq "PCI") {
        "https://devicehunt.com/search/type/pci/vendor/$vendorId/device/$productId"
    } else {
        return $null
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get
        if ($response) {
            # Return only the URL for the device
            return [PSCustomObject]@{
                URL = $url
            }
        }
    } catch {
        Write-Warning "Failed to get data from DeviceHunt for VendorID $vendorId and ProductID $productId"
        return $null
    }
}

# Function to detect DMA devices and validate with DeviceHunt
function Detect-AllDMADevices {
    Write-Host "Detecting all devices and analyzing DMA capabilities..." -ForegroundColor Cyan
    $usbDevices = @()
    $pciDevices = @()
    $otherDevices = @()
    $vulnerableDrivers = @()
    $deviceHuntDevices = @()  # Devices with valid DeviceHuntURL

    $deviceHashSet = @{}  # A hash set to track unique devices by DeviceID

    # Query all devices using Get-CimInstance
    $allDevices = Get-CimInstance -ClassName Win32_PnPEntity
    foreach ($device in $allDevices) {
        $deviceName = $device.Name
        $deviceID = $device.DeviceID
        $description = $device.Description
        $status = $device.Status
        $manufacturer = $device.Manufacturer
        $service = $device.Service

        # Extract VendorID and ProductID for USB devices
        $vendorId = if ($deviceID -match "VID_([0-9A-F]{4})") { $matches[1] } else { $null }
        $productId = if ($deviceID -match "PID_([0-9A-F]{4})") { $matches[1] } else { $null }

        # Extract VendorID and ProductID for PCI devices
        $vendorIdPCI = if ($deviceID -match "VEN_([0-9A-F]{4})") { $matches[1] } else { $null }
        $productIdPCI = if ($deviceID -match "DEV_([0-9A-F]{4})") { $matches[1] } else { $null }

        # Check if VendorID and ProductID exist and query DeviceHunt API
        $deviceData = $null
        if ($vendorId -and $productId) {
            $deviceType = "USB"
            $deviceData = Get-DeviceFromDeviceHunt -vendorId $vendorId -productId $productId -deviceType $deviceType
        } elseif ($vendorIdPCI -and $productIdPCI) {
            $deviceType = "PCI"
            $deviceData = Get-DeviceFromDeviceHunt -vendorId $vendorIdPCI -productId $productIdPCI -deviceType $deviceType
        }

        # If a valid DeviceHunt URL exists, prioritize it by placing it in the deviceHuntDevices list
        if ($deviceData -and $deviceData.URL -like "https*") {
            # Only add unique devices by checking DeviceID
            if (-not $deviceHashSet.ContainsKey($deviceID)) {
                $deviceHuntDevices += [PSCustomObject]@{
                    Name               = $deviceName
                    DeviceID           = $deviceID
                    Description        = $description
                    Status             = $status
                    Manufacturer       = $manufacturer
                    DriverService      = $service
                    DeviceHuntURL      = $deviceData.URL
                }
                $deviceHashSet[$deviceID] = $true  # Mark this device as added
            }
        } elseif ($deviceID -like "USB*") {
            if (-not $deviceHashSet.ContainsKey($deviceID)) {
                $usbDevices += [PSCustomObject]@{
                    Name               = $deviceName
                    DeviceID           = $deviceID
                    Description        = $description
                    Status             = $status
                    Manufacturer       = $manufacturer
                    DriverService      = $service
                    DeviceHuntURL      = if ($deviceData) { $deviceData.URL } else { "Not found" }
                }
                $deviceHashSet[$deviceID] = $true  # Mark this device as added
            }
        } elseif ($deviceID -like "PCI*") {
            if (-not $deviceHashSet.ContainsKey($deviceID)) {
                $pciDevices += [PSCustomObject]@{
                    Name               = $deviceName
                    DeviceID           = $deviceID
                    Description        = $description
                    Status             = $status
                    Manufacturer       = $manufacturer
                    DriverService      = $service
                    DeviceHuntURL      = if ($deviceData) { $deviceData.URL } else { "Not found" }
                }
                $deviceHashSet[$deviceID] = $true  # Mark this device as added
            }
        } else {
            if (-not $deviceHashSet.ContainsKey($deviceID)) {
                $otherDevices += [PSCustomObject]@{
                    Name               = $deviceName
                    DeviceID           = $deviceID
                    Description        = $description
                    Status             = $status
                    Manufacturer       = $manufacturer
                    DriverService      = $service
                    DeviceHuntURL      = if ($deviceData) { $deviceData.URL } else { "Not found" }
                }
                $deviceHashSet[$deviceID] = $true  # Mark this device as added
            }
        }

        # Check if the device has a vulnerable driver or is unsigned
        if ($device.DriverSigned -eq "False") {
            $vulnerableDrivers += [PSCustomObject]@{
                Name               = $deviceName
                DeviceID           = $deviceID
                Description        = $description
                Status             = $status
                Manufacturer       = $manufacturer
                DriverService      = $service
                DeviceHuntURL      = if ($deviceData) { $deviceData.URL } else { "Not found" }
            }
        }
    }

    # Sort the devices within each category (DeviceHunt, USB, PCI, Other) by DeviceID
    $deviceHuntDevices = $deviceHuntDevices | Sort-Object -Property DeviceID
    $usbDevices = $usbDevices | Sort-Object -Property DeviceID
    $pciDevices = $pciDevices | Sort-Object -Property DeviceID
    $otherDevices = $otherDevices | Sort-Object -Property DeviceID

    # Combine DeviceHunt devices first, then USB devices, then PCI devices, and other devices below
    $allSortedDevices = $deviceHuntDevices + $usbDevices + $pciDevices + $otherDevices

    # Return the combined list
    return [PSCustomObject]@{
        AllDevices           = $allSortedDevices
        VulnerableDrivers    = $vulnerableDrivers
    }
}

# Detect all devices and prioritize DeviceHunt URLs first, then USB, PCI, and other devices
Write-Host "Starting device detection..."
$dmaResults = Detect-AllDMADevices

# Count the number of devices and vulnerable drivers found
$deviceCount = ($dmaResults.AllDevices).Count
$vulnerableDriverCount = ($dmaResults.VulnerableDrivers).Count

# Update the window title with the counts
$host.ui.RawUI.WindowTitle = "DMA Detection - Devices: $deviceCount, Vulnerable Drivers: $vulnerableDriverCount"

# Save results to log in C:\ss5
Write-Host "Logging results to $logFilePath..." -ForegroundColor Yellow
$dmaResults.AllDevices | Out-File -FilePath $logFilePath -Append
$dmaResults.VulnerableDrivers | Out-File -FilePath $logFilePath -Append

# Display results in Out-GridView for review with column auto-sizing
Write-Host "DMA Detection Complete. Displaying results..." -ForegroundColor Green

# Ensure Out-GridView is being called correctly
$allDevices = $dmaResults.AllDevices
if ($allDevices) {
    $deviceCount = $allDevices.Count
    $allDevices | Out-GridView -Title "Device Detection - (Devices: $deviceCount)" -PassThru
} else {
    Write-Warning "No devices found for display in Out-GridView." -ForegroundColor Red
}

# Also check for vulnerable drivers
$vulnerableDrivers = $dmaResults.VulnerableDrivers
if ($vulnerableDrivers) {
    $vulnerableCount = $vulnerableDrivers.Count
    $vulnerableDrivers | Out-GridView -Title "Vulnerable/Unsigned Drivers - (Drivers: $vulnerableCount)" -PassThru
} else {
    Write-host "No vulnerable drivers found for display in Out-GridView." -ForegroundColor Green
}

Write-host " "
Read-host "Scan Complete"

