# Blockchain Facts Scanner for PowerShell
# Converted from Go version

# Define blockchain networks and their APIs
$SupportedNetworks = @{
    "eth" = @{
        Name = "Ethereum"
        API = "https://api.etherscan.io/api"
        Explorer = "https://etherscan.io"
    }
    "bsc" = @{
        Name = "Binance Smart Chain"
        API = "https://api.bscscan.com/api"
        Explorer = "https://bscscan.com"
    }
    "polygon" = @{
        Name = "Polygon"
        API = "https://api.polygonscan.com/api"
        Explorer = "https://polygonscan.com"
    }
}

# Define result classes
class Finding {
    [string]$Category
    [string]$Detail
    [string]$Importance

    Finding([string]$category, [string]$detail, [string]$importance) {
        $this.Category = $category
        $this.Detail = $detail
        $this.Importance = $importance
    }
}

class ContractFacts {
    [PSCustomObject]$BasicInfo
    [PSCustomObject]$SecurityFeatures
    [PSCustomObject]$StateManagement
    [PSCustomObject]$InteractionPatterns
    [PSCustomObject]$AssetManagement
    [PSCustomObject]$ProtocolIntegration

    ContractFacts() {
        $this.BasicInfo = [PSCustomObject]@{
            Address = ""
            Network = ""
            Deployed = Get-Date
            Creator = ""
            Verified = $false
        }

        $this.SecurityFeatures = [PSCustomObject]@{
            ReentrancyProtection = $false
            AccessControls = @()
            SafeMathUsage = $false
            PauseFunction = $false
            ProxyPattern = ""
            Upgradeability = ""
            EmergencyFunctions = @()
        }

        $this.StateManagement = [PSCustomObject]@{
            StateVariables = @()
            StorageLayout = @{}
            MutableFunctions = @()
            Events = @()
        }

        $this.InteractionPatterns = [PSCustomObject]@{
            ExternalCalls = @()
            TokenInterfaces = @()
            OracleUsage = @()
            CrossChainCalls = @()
        }

        $this.AssetManagement = [PSCustomObject]@{
            TokenStandard = ""
            HoldsFunds = $false
            AssetTransfers = @()
            ValueLocks = @()
        }

        $this.ProtocolIntegration = [PSCustomObject]@{
            ConnectedProtocols = @()
            Dependencies = @{}
            Permissions = @{}
        }
    }
}

class BlockchainResults {
    [DateTime]$Timestamp
    [string]$Network
    [ContractFacts]$Contract
    [System.Collections.ArrayList]$Findings

    BlockchainResults() {
        $this.Timestamp = Get-Date
        $this.Network = ""
        $this.Contract = [ContractFacts]::new()
        $this.Findings = [System.Collections.ArrayList]::new()
    }
}

# Part 2: Core Checking Functions

function Check-SmartContract {
    param (
        [string]$network,
        [string]$address
    )

    $results = [BlockchainResults]::new()
    $results.Network = $network
    $results.Timestamp = Get-Date

    try {
        # 1. Basic Contract Information
        Get-ContractBasicInfo -network $network -address $address -results $results

        # 2. Security Features
        Check-SecurityFeatures -network $network -address $address -results $results

        # 3. State Management
        Check-StateManagement -network $network -address $address -results $results

        # 4. Interaction Patterns
        Check-InteractionPatterns -network $network -address $address -results $results

        # 5. Asset Management
        Check-AssetManagement -network $network -address $address -results $results

        return $results
    }
    catch {
        Write-Error "Error checking contract: $_"
        return $null
    }
}

function Get-ContractBasicInfo {
    param (
        [string]$network,
        [string]$address,
        [BlockchainResults]$results
    )

    $networkInfo = $SupportedNetworks[$network]
    $apiKey = $env:($network + "_API_KEY")
    
    $url = "$($networkInfo.API)?module=contract&action=getcontractinfo&address=$address"
    if ($apiKey) {
        $url += "&apikey=$apiKey"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get
        
        $results.Contract.BasicInfo.Address = $address
        $results.Contract.BasicInfo.Network = $network

        if ($response.result.verified) {
            $results.Contract.BasicInfo.Verified = $response.result.verified -eq "1"
            $finding = [Finding]::new(
                "Contract Verification",
                "Contract is $( if($results.Contract.BasicInfo.Verified){''}else{'not '})verified",
                "High"
            )
            $results.Findings.Add($finding) | Out-Null
        }
    }
    catch {
        Write-Warning "Error getting basic contract info: $_"
    }
}

function Check-SecurityFeatures {
    param (
        [string]$network,
        [string]$address,
        [BlockchainResults]$results
    )

    $code = Get-ContractCode -network $network -address $address

    # 1. Check Reentrancy Protection
    if ($code -match "nonReentrant|reentrancyGuard") {
        $results.Contract.SecurityFeatures.ReentrancyProtection = $true
        $finding = [Finding]::new(
            "Security Feature",
            "Reentrancy protection implemented",
            "High"
        )
        $results.Findings.Add($finding) | Out-Null
    }

    # 2. Check Access Controls
    $accessControls = @()
    if ($code -match "Ownable") {
        $accessControls += "Ownable"
    }
    if ($code -match "AccessControl") {
        $accessControls += "Role-Based Access Control"
    }
    $results.Contract.SecurityFeatures.AccessControls = $accessControls

    # 3. Check SafeMath Usage
    $results.Contract.SecurityFeatures.SafeMathUsage = 
        $code -match "SafeMath|using SafeMath"

    # 4. Check Pause Functionality
    if ($code -match "Pausable|whenNotPaused") {
        $results.Contract.SecurityFeatures.PauseFunction = $true
        $finding = [Finding]::new(
            "Security Feature",
            "Pause mechanism present",
            "High"
        )
        $results.Findings.Add($finding) | Out-Null
    }
}

function Check-StateManagement {
    param (
        [string]$network,
        [string]$address,
        [BlockchainResults]$results
    )

    $abi = Get-ContractABI -network $network -address $address

    foreach ($item in $abi) {
        # Check state variables
        if ($item.type -eq "state") {
            $results.Contract.StateManagement.StateVariables += $item.name
        }

        # Check mutable functions
        if ($item.type -eq "function" -and -not $item.constant) {
            $results.Contract.StateManagement.MutableFunctions += $item.name
        }

        # Check events
        if ($item.type -eq "event") {
            $results.Contract.StateManagement.Events += $item.name
        }
    }
}

function Check-InteractionPatterns {
    param (
        [string]$network,
        [string]$address,
        [BlockchainResults]$results
    )

    $code = Get-ContractCode -network $network -address $address

    # 1. Check External Calls
    $externalCalls = Find-ExternalCalls -code $code
    if ($externalCalls.Count -gt 0) {
        $results.Contract.InteractionPatterns.ExternalCalls = $externalCalls
        $finding = [Finding]::new(
            "Interaction Pattern",
            "Contract makes $($externalCalls.Count) external calls",
            "Medium"
        )
        $results.Findings.Add($finding) | Out-Null
    }

    # 2. Check Token Interfaces
    foreach ($standard in @("ERC20", "ERC721", "ERC1155")) {
        if ($code -match $standard) {
            $results.Contract.InteractionPatterns.TokenInterfaces += $standard
        }
    }

    # 3. Check Oracle Usage
    if ($code -match "Chainlink|AggregatorV3Interface") {
        $results.Contract.InteractionPatterns.OracleUsage += "Chainlink"
    }
}

function Check-AssetManagement {
    param (
        [string]$network,
        [string]$address,
        [BlockchainResults]$results
    )

    $code = Get-ContractCode -network $network -address $address

    # 1. Determine Token Standard
    foreach ($standard in @("ERC20", "ERC721", "ERC1155")) {
        if ($code -match $standard) {
            $results.Contract.AssetManagement.TokenStandard = $standard
            break
        }
    }

    # 2. Check if contract holds funds
    $balance = Get-ContractBalance -network $network -address $address
    $results.Contract.AssetManagement.HoldsFunds = [decimal]$balance -gt 0

    # 3. Analyze value transfers
    $transfers = Get-ValueTransfers -network $network -address $address
    $results.Contract.AssetManagement.AssetTransfers = $transfers

    if ($results.Contract.AssetManagement.HoldsFunds) {
        $finding = [Finding]::new(
            "Asset Management",
            "Contract holds funds",
            "High"
        )
        $results.Findings.Add($finding) | Out-Null
    }
}

# Part 3: Output Formatting and Results Processing

function Process-Results {
    param (
        [BlockchainResults]$results
    )

    Write-Host "`nBlockchain Facts Scanner Results" -ForegroundColor Cyan
    Write-Host ("=" * 80)
    Write-Host "Timestamp: $($results.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Host "Network: $($results.Network)`n"

    if ($results.Contract) {
        Write-Host "Smart Contract Analysis" -ForegroundColor Yellow
        Write-Host ("-" * 80)
        
        # Basic Info
        Write-Host "Basic Information:" -ForegroundColor Green
        Write-Host "Address: $($results.Contract.BasicInfo.Address)"
        Write-Host "Verified: $($results.Contract.BasicInfo.Verified)"
        Write-Host "Creator: $($results.Contract.BasicInfo.Creator)`n"

        # Security Features
        Write-Host "Security Features:" -ForegroundColor Green
        Write-Host "- Reentrancy Protection: $($results.Contract.SecurityFeatures.ReentrancyProtection)"
        Write-Host "- Access Controls: $($results.Contract.SecurityFeatures.AccessControls -join ', ')"
        Write-Host "- SafeMath Usage: $($results.Contract.SecurityFeatures.SafeMathUsage)"
        Write-Host "- Pause Function: $($results.Contract.SecurityFeatures.PauseFunction)"
        Write-Host "- Proxy Pattern: $($results.Contract.SecurityFeatures.ProxyPattern)"
        Write-Host "- Upgradeability: $($results.Contract.SecurityFeatures.Upgradeability)`n"

        # State Management
        Write-Host "State Management:" -ForegroundColor Green
        Write-Host "- State Variables: $($results.Contract.StateManagement.StateVariables.Count) found"
        Write-Host "- Mutable Functions: $($results.Contract.StateManagement.MutableFunctions.Count) found"
        Write-Host "- Events: $($results.Contract.StateManagement.Events.Count) defined`n"

        # Interaction Patterns
        Write-Host "Interaction Patterns:" -ForegroundColor Green
        Write-Host "- External Calls: $($results.Contract.InteractionPatterns.ExternalCalls.Count) found"
        Write-Host "- Token Interfaces: $($results.Contract.InteractionPatterns.TokenInterfaces -join ', ')"
        Write-Host "- Oracle Usage: $($results.Contract.InteractionPatterns.OracleUsage -join ', ')`n"

        # Asset Management
        Write-Host "Asset Management:" -ForegroundColor Green
        Write-Host "- Token Standard: $($results.Contract.AssetManagement.TokenStandard)"
        Write-Host "- Holds Funds: $($results.Contract.AssetManagement.HoldsFunds)"
        Write-Host "- Asset Transfers: $($results.Contract.AssetManagement.AssetTransfers.Count) recorded`n"
    }

    # Key Findings
    Write-Host "Key Findings:" -ForegroundColor Magenta
    Write-Host ("-" * 80)
    foreach ($finding in $results.Findings) {
        $color = switch ($finding.Importance) {
            "High" { "Red" }
            "Medium" { "Yellow" }
            "Low" { "Green" }
            default { "White" }
        }
        Write-Host "[$($finding.Importance)] $($finding.Category): " -NoNewline -ForegroundColor $color
        Write-Host "$($finding.Detail)"
    }
}

function Save-Results {
    param (
        [BlockchainResults]$results
    )

    $filename = "blockchain_facts_$($results.Network)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    
    try {
        # Convert results to JSON
        $jsonResults = $results | ConvertTo-Json -Depth 10

        # Save to file
        $jsonResults | Out-File -FilePath $filename -Encoding UTF8
        
        Write-Host "`nResults saved to: $filename" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Error saving results: $_"
        return $false
    }
}

function Format-FindingSeverity {
    param (
        [string]$severity,
        [string]$text
    )

    $color = switch ($severity) {
        "High" { "Red" }
        "Medium" { "Yellow" }
        "Low" { "Green" }
        default { "White" }
    }

    Write-Host $text -ForegroundColor $color
}

function Export-ResultsToHTML {
    param (
        [BlockchainResults]$results
    )

    $filename = "blockchain_facts_$($results.Network)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    $html = @"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Blockchain Facts Scanner Results</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .section { margin: 20px 0; }
            .finding-high { color: red; }
            .finding-medium { color: orange; }
            .finding-low { color: green; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>Blockchain Facts Scanner Results</h1>
        <div class="section">
            <h2>Basic Information</h2>
            <p>Network: $($results.Network)</p>
            <p>Timestamp: $($results.Timestamp)</p>
            <p>Contract Address: $($results.Contract.BasicInfo.Address)</p>
        </div>
"@

    # Add sections for each analysis type
    $sections = @(
        @{ Title = "Security Features"; Data = $results.Contract.SecurityFeatures },
        @{ Title = "State Management"; Data = $results.Contract.StateManagement },
        @{ Title = "Interaction Patterns"; Data = $results.Contract.InteractionPatterns },
        @{ Title = "Asset Management"; Data = $results.Contract.AssetManagement }
    )

    foreach ($section in $sections) {
        $html += "<div class='section'><h2>$($section.Title)</h2><table>"
        foreach ($property in $section.Data.PSObject.Properties) {
            $html += "<tr><td>$($property.Name)</td><td>$($property.Value)</td></tr>"
        }
        $html += "</table></div>"
    }

    # Add findings
    $html += "<div class='section'><h2>Findings</h2><ul>"
    foreach ($finding in $results.Findings) {
        $html += "<li class='finding-$($finding.Importance.ToLower())'>"
        $html += "[$($finding.Importance)] $($finding.Category): $($finding.Detail)"
        $html += "</li>"
    }
    $html += "</ul></div></body></html>"

    try {
        $html | Out-File -FilePath $filename -Encoding UTF8
        Write-Host "`nHTML report saved to: $filename" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Error saving HTML report: $_"
        return $false
    }
}

# Part 4: Main Program and Utilities

function Get-ContractCode {
    param (
        [string]$network,
        [string]$address
    )

    $networkInfo = $SupportedNetworks[$network]
    $apiKey = $env:($network + "_API_KEY")
    
    $url = "$($networkInfo.API)?module=contract&action=getsourcecode&address=$address"
    if ($apiKey) {
        $url += "&apikey=$apiKey"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get
        if ($response.result -and $response.result[0].SourceCode) {
            return $response.result[0].SourceCode
        }
    }
    catch {
        Write-Warning "Error getting contract code: $_"
    }
    return ""
}

function Get-ContractABI {
    param (
        [string]$network,
        [string]$address
    )

    $networkInfo = $SupportedNetworks[$network]
    $apiKey = $env:($network + "_API_KEY")
    
    $url = "$($networkInfo.API)?module=contract&action=getabi&address=$address"
    if ($apiKey) {
        $url += "&apikey=$apiKey"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get
        if ($response.result) {
            return $response.result | ConvertFrom-Json
        }
    }
    catch {
        Write-Warning "Error getting contract ABI: $_"
    }
    return @()
}

function Get-ContractBalance {
    param (
        [string]$network,
        [string]$address
    )

    $networkInfo = $SupportedNetworks[$network]
    $apiKey = $env:($network + "_API_KEY")
    
    $url = "$($networkInfo.API)?module=account&action=balance&address=$address"
    if ($apiKey) {
        $url += "&apikey=$apiKey"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get
        if ($response.result) {
            return [decimal]$response.result / 1e18  # Convert from Wei to Ether
        }
    }
    catch {
        Write-Warning "Error getting contract balance: $_"
    }
    return 0
}

function Get-ValueTransfers {
    param (
        [string]$network,
        [string]$address
    )

    $networkInfo = $SupportedNetworks[$network]
    $apiKey = $env:($network + "_API_KEY")
    
    $url = "$($networkInfo.API)?module=account&action=txlist&address=$address"
    if ($apiKey) {
        $url += "&apikey=$apiKey"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get
        return $response.result | Where-Object { $_.value -gt 0 }
    }
    catch {
        Write-Warning "Error getting value transfers: $_"
    }
    return @()
}

function Find-ExternalCalls {
    param (
        [string]$code
    )

    $externalCalls = @()
    $patterns = @(
        'call\(',
        'delegatecall',
        'staticcall',
        'transfer\(',
        'send\(',
        'callcode\('
    )

    foreach ($pattern in $patterns) {
        if ($code -match $pattern) {
            $externalCalls += $pattern.TrimEnd('\(')
        }
    }

    return $externalCalls
}

function Process-ContractsList {
    param (
        [string]$filePath
    )

    if (-not (Test-Path $filePath)) {
        Write-Error "File not found: $filePath"
        return
    }

    $contracts = Get-Content $filePath | Where-Object { $_ -match '\S' }
    $totalContracts = $contracts.Count
    $currentContract = 0

    foreach ($contract in $contracts) {
        $currentContract++
        $parts = $contract.Split(',').Trim()
        
        if ($parts.Count -ne 2) {
            Write-Warning "Invalid format for contract: $contract"
            continue
        }

        $network = $parts[0]
        $address = $parts[1]

        Write-Progress -Activity "Scanning Contracts" -Status "Processing $currentContract of $totalContracts" `
            -PercentComplete (($currentContract / $totalContracts) * 100)

        Write-Host "`nProcessing contract $currentContract/$totalContracts" -ForegroundColor Cyan
        Write-Host "Network: $network, Address: $address"

        $results = Check-SmartContract -network $network -address $address
        if ($results) {
            Process-Results -results $results
            Save-Results -results $results
            Export-ResultsToHTML -results $results
        }
    }

    Write-Progress -Activity "Scanning Contracts" -Completed
}

# Main program execution
function Start-BlockchainScanner {
    Clear-Host
    Write-Host "Blockchain Facts Scanner" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    Write-Host "1. Check a single Smart Contract"
    Write-Host "2. Check multiple contracts from file"
    Write-Host "3. Exit"

    $choice = Read-Host "`nEnter your choice (1-3)"

    switch ($choice) {
        "1" {
            Write-Host "`nAvailable Networks:" -ForegroundColor Yellow
            $SupportedNetworks.Keys | ForEach-Object { Write-Host "- $_" }
            
            $network = Read-Host "`nEnter network (eth/bsc/polygon)"
            if (-not $SupportedNetworks.ContainsKey($network)) {
                Write-Host "Invalid network selected." -ForegroundColor Red
                return
            }

            $address = Read-Host "Enter contract address"
            $results = Check-SmartContract -network $network -address $address
            
            if ($results) {
                Process-Results -results $results
                Save-Results -results $results
                Export-ResultsToHTML -results $results
            }
        }
        "2" {
            $filePath = Read-Host "Enter path to contracts list file (default: contracts.txt)"
            if (-not $filePath) {
                $filePath = "contracts.txt"
            }
            Process-ContractsList -filePath $filePath
        }
        "3" {
            Write-Host "Exiting..." -ForegroundColor Yellow
            return
        }
        default {
            Write-Host "Invalid choice. Please select 1-3." -ForegroundColor Red
        }
    }
}

# Script execution entry point
if ($MyInvocation.InvocationName -ne '.') {
    Start-BlockchainScanner
}
