Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Get-PowerShellRiskFindings {
    $patterns = @(
        @{ Name = 'Invoke-Expression'; Regex = '(?i)\b(Invoke-Expression|iex)\b'; Severity = 'High'; Why = 'Runs arbitrary strings as code.' },
        @{ Name = 'EncodedCommand'; Regex = '(?i)-enc(odedcommand)?\b'; Severity = 'High'; Why = 'Obfuscates command content.' },
        @{ Name = 'DownloadString'; Regex = '(?i)DownloadString\s*\('; Severity = 'High'; Why = 'Pulls remote script text.' },
        @{ Name = 'Invoke-WebRequest'; Regex = '(?i)\b(iwr|Invoke-WebRequest)\b'; Severity = 'Medium'; Why = 'Downloads remote content.' },
        @{ Name = 'Invoke-RestMethod'; Regex = '(?i)\b(irm|Invoke-RestMethod)\b'; Severity = 'Medium'; Why = 'Calls remote APIs/content.' },
        @{ Name = 'Net.WebClient'; Regex = '(?i)Net\.WebClient'; Severity = 'High'; Why = 'Legacy download/execution path.' },
        @{ Name = 'BypassPolicy'; Regex = '(?i)-ExecutionPolicy\s+Bypass'; Severity = 'High'; Why = 'Bypasses script execution controls.' },
        @{ Name = 'DisableDefender'; Regex = '(?i)Set-MpPreference\b.*(DisableRealtimeMonitoring|DisableIOAVProtection)'; Severity = 'Critical'; Why = 'Weakens built-in AV controls.' },
        @{ Name = 'AddExclusion'; Regex = '(?i)Add-MpPreference\b.*Exclusion'; Severity = 'High'; Why = 'Creates AV blind spots.' },
        @{ Name = 'CredentialHarvest'; Regex = '(?i)(Get-Credential|ConvertTo-SecureString\s+.+-AsPlainText)'; Severity = 'Medium'; Why = 'Potential credential handling risk.' },
        @{ Name = 'ProcessInjection'; Regex = '(?i)(Start-Process\s+.+-Verb\s+RunAs|rundll32|regsvr32)'; Severity = 'Medium'; Why = 'Living-off-the-land execution vectors.' }
    )

    $sources = New-Object System.Collections.Generic.List[object]

    $historyPath = $null
    try {
        if (Get-Command Get-PSReadLineOption -ErrorAction SilentlyContinue) {
            $historyPath = (Get-PSReadLineOption).HistorySavePath
        }
    } catch {}
    if ($historyPath -and (Test-Path $historyPath)) {
        $sources.Add([pscustomobject]@{ Name = 'PSReadLineHistory'; Path = $historyPath; Type = 'file' })
    }

    $legacyHistory = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if ((Test-Path $legacyHistory) -and ($legacyHistory -ne $historyPath)) {
        $sources.Add([pscustomobject]@{ Name = 'LegacyHistory'; Path = $legacyHistory; Type = 'file' })
    }

    $transcriptRoot = Join-Path $env:USERPROFILE 'Documents'
    if (Test-Path $transcriptRoot) {
        Get-ChildItem -Path $transcriptRoot -Filter '*PowerShell_transcript*' -Recurse -File -ErrorAction SilentlyContinue |
            Select-Object -First 15 |
            ForEach-Object {
                $sources.Add([pscustomobject]@{ Name = 'Transcript'; Path = $_.FullName; Type = 'file' })
            }
    }

    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($src in $sources) {
        if ($src.Type -eq 'file') {
            try {
                $lineNo = 0
                Get-Content -Path $src.Path -ErrorAction Stop | ForEach-Object {
                    $lineNo++
                    $line = [string]$_
                    foreach ($p in $patterns) {
                        if ($line -match $p.Regex) {
                            $findings.Add([pscustomobject]@{
                                Severity = $p.Severity
                                Pattern = $p.Name
                                Source = $src.Name
                                Location = "$($src.Path):$lineNo"
                                Evidence = $line.Trim()
                                Why = $p.Why
                            })
                        }
                    }
                }
            } catch {}
        }
    }

    foreach ($logName in @('Microsoft-Windows-PowerShell/Operational','Windows PowerShell')) {
        try {
            $events = Get-WinEvent -LogName $logName -MaxEvents 250 -ErrorAction Stop |
                Where-Object { $_.Id -in 4103, 4104, 400, 403 }
            foreach ($event in $events) {
                $text = [string]$event.Message
                if (-not $text) { continue }
                foreach ($p in $patterns) {
                    if ($text -match $p.Regex) {
                        $flat = [string]($text -replace '\s+', ' ')
                        $evidence = if ([string]::IsNullOrWhiteSpace($flat)) {
                            '(empty event message)'
                        } elseif ($flat.Length -gt 180) {
                            $flat.Substring(0, 180)
                        } else {
                            $flat
                        }
                        $findings.Add([pscustomobject]@{
                            Severity = $p.Severity
                            Pattern = $p.Name
                            Source = "EventLog:$logName"
                            Location = "EventID $($event.Id) @ $($event.TimeCreated)"
                            Evidence = $evidence
                            Why = $p.Why
                        })
                    }
                }
            }
        } catch {}
    }

    $severityRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $findings |
        Sort-Object @{Expression = { $severityRank[$_.Severity] }}, Pattern, Source |
        Select-Object -Unique Severity, Pattern, Source, Location, Evidence, Why
}

function Get-ListeningTcpPorts {
    try {
        return Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Select-Object -ExpandProperty LocalPort -Unique |
            Sort-Object
    } catch {
        return @()
    }
}

function Get-ListeningTcpPortDetails {
    try {
        $rows = Get-NetTCPConnection -State Listen -ErrorAction Stop
    } catch {
        return @()
    }
    $details = New-Object System.Collections.Generic.List[object]
    foreach ($row in $rows) {
        $procName = ''
        try {
            if ($row.OwningProcess -gt 0) {
                $procName = (Get-Process -Id $row.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            }
        } catch {}
        $details.Add([pscustomobject]@{
            Port = [int]$row.LocalPort
            Address = [string]$row.LocalAddress
            ProcessId = [int]$row.OwningProcess
            ProcessName = if ($procName) { $procName } else { 'unknown' }
            PublicFacing = ($row.LocalAddress -in @('0.0.0.0','::','*'))
        })
    }
    return $details | Sort-Object Port, Address -Unique
}

function Get-EnvironmentContextInfo {
    $isDomainJoined = $false
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $isDomainJoined = [bool]$cs.PartOfDomain
    } catch {}
    $publicProfileDefaultBlock = $false
    try {
        $pub = Get-NetFirewallProfile -Name Public -ErrorAction Stop
        $publicProfileDefaultBlock = ($pub.DefaultInboundAction -eq 'Block')
    } catch {}
    return [pscustomobject]@{
        IsDomainJoined = $isDomainJoined
        PublicInboundDefaultBlock = $publicProfileDefaultBlock
    }
}

function Get-BehaviorCorrelationAlerts {
    param(
        [Parameter(Mandatory)]
        [object]$Findings,
        [Parameter(Mandatory)]
        [object]$PortDetails
    )

    $alerts = @()
    $f = @($Findings)
    $p = @($PortDetails)
    $hasEncoded = ($f | Where-Object Pattern -eq 'EncodedCommand').Count -gt 0
    $hasBypass = ($f | Where-Object Pattern -eq 'BypassPolicy').Count -gt 0
    $hasWebPull = ($f | Where-Object Pattern -in @('DownloadString','Invoke-WebRequest','Invoke-RestMethod','Net.WebClient')).Count -gt 0
    $hasRemoteAdmin = ($p | Where-Object { $_.Port -in @(3389,5985,5986,445) -and $_.PublicFacing }).Count -gt 0
    $hasDefenderTamper = ($f | Where-Object Pattern -in @('DisableDefender','AddExclusion')).Count -gt 0

    if ($hasEncoded -and $hasBypass -and $hasWebPull) {
        $alerts += [pscustomobject]@{ Risk = 'High'; Pattern = 'Potential Living-Off-The-Land behavior'; Evidence = 'EncodedCommand + ExecutionPolicy bypass + network pull behavior'; Interpretation = 'Possible staged payload execution or lateral movement preparation.' }
    }
    if ($hasBypass -and $hasRemoteAdmin) {
        $alerts += [pscustomobject]@{ Risk = 'High'; Pattern = 'Remote admin exposure with weakened script controls'; Evidence = 'ExecutionPolicy bypass found with public-facing admin/service ports'; Interpretation = 'Increased risk of remote post-exploitation tooling.' }
    }
    if ($hasDefenderTamper -and $hasWebPull) {
        $alerts += [pscustomobject]@{ Risk = 'High'; Pattern = 'Defense evasion + remote content retrieval'; Evidence = 'Defender tamper signals plus web download/execution indicators'; Interpretation = 'Potential malware delivery and AV bypass sequence.' }
    }
    return ,$alerts
}

function Get-SecurityPostureSummary {
    param(
        [Parameter(Mandatory)]
        [object[]]$Findings,
        [Parameter(Mandatory)]
        [object[]]$PortDetails,
        [Parameter(Mandatory)]
        [object]$Context
    )

    $score = 100
    $drivers = New-Object System.Collections.Generic.List[string]
    $criticalCount = ($Findings | Where-Object Severity -eq 'Critical').Count
    $highCount = ($Findings | Where-Object Severity -eq 'High').Count
    $medCount = ($Findings | Where-Object Severity -eq 'Medium').Count
    $score -= ($criticalCount * 8)
    $score -= ($highCount * 3)
    $score -= ($medCount * 1)
    if (($PortDetails | Where-Object { $_.Port -eq 445 -and $_.PublicFacing }).Count -gt 0) { $score -= 15; $drivers.Add('SMB exposed publicly (445)') }
    if (($Findings | Where-Object Pattern -eq 'BypassPolicy').Count -gt 0) { $score -= 10; $drivers.Add('ExecutionPolicy bypass usage detected') }
    if (($Findings | Where-Object Pattern -in @('DisableDefender','AddExclusion')).Count -gt 0) { $score -= 14; $drivers.Add('Defender tamper attempts detected') }
    if (-not $Context.PublicInboundDefaultBlock) { $score -= 8; $drivers.Add('Public firewall profile not blocking inbound by default') }
    if ($Context.IsDomainJoined) { $score -= 2 }
    if ($score -lt 0) { $score = 0 }
    if ($score -gt 100) { $score = 100 }

    $riskLevel = if ($score -ge 85) { 'Low' } elseif ($score -ge 70) { 'Guarded' } elseif ($score -ge 50) { 'Elevated' } else { 'High' }
    $topDrivers = @($drivers | Select-Object -First 3)
    while ($topDrivers.Count -lt 3) { $topDrivers += 'No additional major risk driver detected.' }
    return [pscustomobject]@{ Score = [int]$score; RiskLevel = $riskLevel; TopDrivers = $topDrivers }
}

function Preview-HardeningFix {
    param([Parameter(Mandatory)][string]$FixId)
    switch ($FixId) {
        'restrict_smb_private' { 'Will create/update firewall rule to block inbound TCP 445 on Public profile only.' }
        'enforce_allsigned' { 'Will set CurrentUser ExecutionPolicy to AllSigned (recording previous value for rollback).' }
        'reenable_defender' { 'Will set Defender real-time and IOAV protections to enabled (recording current values for rollback).' }
        default { 'Unknown fix selection.' }
    }
}

function Apply-HardeningFix {
    param([Parameter(Mandatory)][string]$FixId,[Parameter(Mandatory)][hashtable]$RollbackState)
    switch ($FixId) {
        'restrict_smb_private' {
            $ruleName = 'Hardening_SMB445_Block_Public'
            if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Block -Enabled True -Protocol TCP -LocalPort 445 -Profile Public | Out-Null
            }
            $RollbackState['restrict_smb_private'] = @{ RuleName = $ruleName }
            "Applied: SMB restricted on Public profile (rule: $ruleName)."
        }
        'enforce_allsigned' {
            $oldPolicy = Get-ExecutionPolicy -Scope CurrentUser
            $RollbackState['enforce_allsigned'] = @{ PreviousPolicy = $oldPolicy }
            Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope CurrentUser -Force
            "Applied: CurrentUser execution policy set to AllSigned (previous: $oldPolicy)."
        }
        'reenable_defender' {
            $pref = Get-MpPreference -ErrorAction SilentlyContinue
            if ($pref) { $RollbackState['reenable_defender'] = @{ DisableRealtimeMonitoring = [bool]$pref.DisableRealtimeMonitoring; DisableIOAVProtection = [bool]$pref.DisableIOAVProtection } }
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            Set-MpPreference -DisableIOAVProtection $false -ErrorAction Stop
            'Applied: Defender real-time and IOAV protection enabled.'
        }
        default { 'No fix was applied: unknown selection.' }
    }
}

function Rollback-HardeningFix {
    param([Parameter(Mandatory)][string]$FixId,[Parameter(Mandatory)][hashtable]$RollbackState)
    if (-not $RollbackState.ContainsKey($FixId)) { return 'No rollback snapshot found for this fix.' }
    switch ($FixId) {
        'restrict_smb_private' {
            $ruleName = $RollbackState[$FixId]['RuleName']
            if ($ruleName) { Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
            "Rolled back: removed firewall rule $ruleName."
        }
        'enforce_allsigned' {
            $prev = $RollbackState[$FixId]['PreviousPolicy']
            Set-ExecutionPolicy -ExecutionPolicy $prev -Scope CurrentUser -Force
            "Rolled back: CurrentUser execution policy restored to $prev."
        }
        'reenable_defender' {
            $s = $RollbackState[$FixId]
            Set-MpPreference -DisableRealtimeMonitoring $s.DisableRealtimeMonitoring -ErrorAction SilentlyContinue
            Set-MpPreference -DisableIOAVProtection $s.DisableIOAVProtection -ErrorAction SilentlyContinue
            'Rolled back: Defender preference values restored.'
        }
        default { 'Rollback skipped: unknown selection.' }
    }
}

function Get-ComplianceChecklist {
    param(
        [Parameter(Mandatory)]
        [object]$PortDetails,
        [Parameter(Mandatory)]
        [object]$Context
    )

    $checks = @()
    $pd = @($PortDetails)
    $execPolicy = Get-ExecutionPolicy -Scope CurrentUser
    $checks += [pscustomobject]@{ Check = 'ExecutionPolicy CurrentUser is AllSigned'; Status = $(if ($execPolicy -eq 'AllSigned') { 'PASS' } else { 'FAIL' }); Detail = "Current: $execPolicy" }

    $defOk = $false
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $defOk = (-not $pref.DisableRealtimeMonitoring -and -not $pref.DisableIOAVProtection)
    } catch {}
    $checks += [pscustomobject]@{ Check = 'Defender Real-time + IOAV enabled'; Status = $(if ($defOk) { 'PASS' } else { 'FAIL' }); Detail = 'Expected both protections enabled.' }

    $public445 = ($pd | Where-Object { $_.Port -eq 445 -and $_.PublicFacing }).Count -gt 0
    $checks += [pscustomobject]@{ Check = 'SMB 445 not public-facing'; Status = $(if (-not $public445) { 'PASS' } else { 'FAIL' }); Detail = $(if ($public445) { 'Port 445 bound to 0.0.0.0/::' } else { 'No public SMB listener detected.' }) }

    $checks += [pscustomobject]@{ Check = 'Public firewall default inbound action'; Status = $(if ($Context.PublicInboundDefaultBlock) { 'PASS' } else { 'FAIL' }); Detail = $(if ($Context.PublicInboundDefaultBlock) { 'Inbound blocked by default.' } else { 'Inbound not blocked by default.' }) }
    return ,$checks
}

function Set-GridData {
    param(
        [Parameter(Mandatory)]
        [System.Windows.Forms.DataGridView]$Grid,
        [Parameter(Mandatory)]
        [object[]]$Rows
    )

    $Grid.DataSource = $null
    $Grid.Columns.Clear()
    $Grid.AutoGenerateColumns = $true

    $rowsArray = @($Rows)
    if ($rowsArray.Count -eq 0) {
        $Grid.Refresh()
        return
    }

    $columnNames = @()
    $first = $rowsArray[0]
    if ($first -is [System.Collections.IDictionary]) {
        $columnNames = @($first.Keys)
    } else {
        $columnNames = @(
            $first.PSObject.Properties |
            Where-Object { $_.MemberType -in @('NoteProperty','Property') } |
            ForEach-Object { $_.Name }
        )
    }

    $table = New-Object System.Data.DataTable
    foreach ($name in $columnNames) {
        [void]$table.Columns.Add([string]$name)
    }

    foreach ($item in $rowsArray) {
        $row = $table.NewRow()
        foreach ($name in $columnNames) {
            $value = $null
            if ($item -is [System.Collections.IDictionary]) {
                if ($item.Contains($name)) { $value = $item[$name] }
            } else {
                $prop = $item.PSObject.Properties[$name]
                if ($prop) { $value = $prop.Value }
            }
            $cellText = if ($null -eq $value) { '' } else { [string]$value }
            if ($name -eq 'Evidence' -and $cellText.Length -gt 140) {
                $cellText = $cellText.Substring(0, 140) + ' ...'
            }
            $row[$name] = $cellText
        }
        [void]$table.Rows.Add($row)
    }

    $Grid.DataSource = $table
    # Size columns to content once, then allow manual drag-resize by the user.
    $Grid.AutoResizeColumns([System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::DisplayedCells)
    $Grid.AutoSizeColumnsMode = 'None'
    if ($Grid.Columns.Contains('Evidence')) {
        $Grid.Columns['Evidence'].Width = 360
        $Grid.Columns['Evidence'].MinimumWidth = 220
    }
    $Grid.Refresh()
}

function Set-GridZoom {
    param(
        [Parameter(Mandatory)]
        [System.Windows.Forms.DataGridView]$Grid,
        [Parameter(Mandatory)]
        [int]$Percent
    )

    $safePercent = [Math]::Max(70, [Math]::Min(140, $Percent))
    $fontSize = [Math]::Round((8.0 * $safePercent / 100.0), 1)
    $font = New-Object System.Drawing.Font('Segoe UI', $fontSize)
    $Grid.Font = $font
    $Grid.ColumnHeadersDefaultCellStyle.Font = $font

    $rowHeight = [Math]::Max(18, [int][Math]::Round(22 * $safePercent / 100.0))
    $Grid.RowTemplate.Height = $rowHeight
    foreach ($row in $Grid.Rows) {
        $row.Height = $rowHeight
    }
    $Grid.Refresh()
}

function Get-ScrollThicknessFromZoom {
    param(
        [Parameter(Mandatory)]
        [int]$Percent
    )

    $safePercent = [Math]::Max(70, [Math]::Min(140, $Percent))
    # Keep bars easy to grab; slightly thicker as zoom increases.
    return [Math]::Max(12, [Math]::Min(20, [int][Math]::Round(14 * $safePercent / 100.0)))
}

function Layout-AuditViewport {
    param(
        [Parameter(Mandatory)]
        [System.Windows.Forms.TabPage]$Tab,
        [Parameter(Mandatory)]
        [System.Windows.Forms.DataGridView]$Grid,
        [Parameter(Mandatory)]
        [System.Windows.Forms.VScrollBar]$VBar,
        [Parameter(Mandatory)]
        [System.Windows.Forms.HScrollBar]$HBar,
        [Parameter(Mandatory)]
        [int]$Thickness,
        [int]$TopScrollY = 82
    )

    $leftMargin = 12
    $rightMargin = 12
    $bottomMargin = 10
    $gap = 8
    $hbarX = $leftMargin + $Thickness + $gap
    $hbarWidth = [Math]::Max(120, $Tab.ClientSize.Width - $hbarX - $rightMargin)

    $HBar.Location = New-Object System.Drawing.Point($hbarX, $topScrollY)
    $HBar.Size = New-Object System.Drawing.Size($hbarWidth, $Thickness)

    $gridY = $topScrollY + $Thickness + 10
    $gridWidth = [Math]::Max(120, $Tab.ClientSize.Width - $hbarX - $rightMargin)
    $gridHeight = [Math]::Max(120, $Tab.ClientSize.Height - $gridY - $bottomMargin)
    $Grid.Location = New-Object System.Drawing.Point($hbarX, $gridY)
    $Grid.Size = New-Object System.Drawing.Size($gridWidth, $gridHeight)

    $VBar.Location = New-Object System.Drawing.Point($leftMargin, $gridY)
    $VBar.Size = New-Object System.Drawing.Size($Thickness, $gridHeight)
}

function Update-AuditVirtualScrollBars {
    param(
        [Parameter(Mandatory)]
        [System.Windows.Forms.DataGridView]$Grid,
        [Parameter(Mandatory)]
        [System.Windows.Forms.VScrollBar]$VBar,
        [Parameter(Mandatory)]
        [System.Windows.Forms.HScrollBar]$HBar
    )

    $rowCount = $Grid.RowCount
    if ($rowCount -le 0) {
        $VBar.Enabled = $true
        $VBar.Minimum = 0
        $VBar.Maximum = 1
        $VBar.LargeChange = 1
        $VBar.SmallChange = 1
        $VBar.Value = 0
    } else {
        $maxRowIndex = $rowCount - 1
        $visibleRows = [Math]::Max(1, $Grid.DisplayedRowCount($false))
        $VBar.Enabled = $true
        $VBar.Minimum = 0
        $VBar.SmallChange = [Math]::Max(1, [int][Math]::Ceiling($visibleRows / 3.0))
        $VBar.LargeChange = $visibleRows
        $VBar.Maximum = $maxRowIndex + $VBar.LargeChange - 1

        $currentRow = 0
        try { $currentRow = $Grid.FirstDisplayedScrollingRowIndex } catch { $currentRow = 0 }
        if ($currentRow -lt 0) { $currentRow = 0 }
        if ($currentRow -gt $maxRowIndex) { $currentRow = $maxRowIndex }
        if ($VBar.Value -ne $currentRow) { $VBar.Value = $currentRow }
    }

    $totalColumnWidth = 0
    foreach ($col in $Grid.Columns) {
        if ($col.Visible) {
            $totalColumnWidth += $col.Width
        }
    }
    $visibleWidth = [Math]::Max(1, $Grid.ClientSize.Width)
    $hMax = [Math]::Max(0, $totalColumnWidth - $visibleWidth)
    if ($hMax -le 0) {
        $HBar.Enabled = $true
        $HBar.Minimum = 0
        $HBar.Maximum = 1
        $HBar.LargeChange = 1
        $HBar.SmallChange = 1
        $HBar.Value = 0
    } else {
        $HBar.Enabled = $true
        $HBar.Minimum = 0
        $HBar.SmallChange = 16
        $HBar.LargeChange = $visibleWidth
        $HBar.Maximum = $hMax + $HBar.LargeChange - 1

        $offset = [Math]::Max(0, [Math]::Min($hMax, $Grid.HorizontalScrollingOffset))
        if ($HBar.Value -ne $offset) { $HBar.Value = $offset }
    }
}

function Get-ThreatRemediationPlan {
    param(
        [Parameter(Mandatory)]
        [object]$Finding
    )

    switch ($Finding.Pattern) {
        'Invoke-Expression' {
            return [pscustomobject]@{
                Analysis = 'Dynamic code execution was detected (Invoke-Expression/iex).'
                Procedure = 'Replace dynamic command strings with fixed script logic; remove risky one-liners from history.'
            }
        }
        'EncodedCommand' {
            return [pscustomobject]@{
                Analysis = 'Base64 encoded command usage can hide malicious behavior.'
                Procedure = 'Decode and review all encoded commands; remove unknown entries; enforce script signing for admin automation.'
            }
        }
        'DownloadString' {
            return [pscustomobject]@{
                Analysis = 'Remote script content download detected.'
                Procedure = 'Stop direct web-to-execution flow; download to file, verify source/hash, then execute with least privilege.'
            }
        }
        'Invoke-WebRequest' {
            return [pscustomobject]@{
                Analysis = 'Remote content retrieval command detected.'
                Procedure = 'Validate destination domains and intent; remove unused download commands from persistent history.'
            }
        }
        'Invoke-RestMethod' {
            return [pscustomobject]@{
                Analysis = 'Remote API/content calls were detected in PowerShell history or logs.'
                Procedure = 'Confirm each endpoint is trusted and necessary; remove unknown API command history entries.'
            }
        }
        'Net.WebClient' {
            return [pscustomobject]@{
                Analysis = 'Legacy .NET WebClient download path detected.'
                Procedure = 'Migrate to safer, explicit download workflows and remove unsafe historical entries.'
            }
        }
        'BypassPolicy' {
            return [pscustomobject]@{
                Analysis = 'Execution policy bypass command detected.'
                Procedure = 'Set CurrentUser execution policy to RemoteSigned and remove bypass commands from command history.'
            }
        }
        'DisableDefender' {
            return [pscustomobject]@{
                Analysis = 'Defender protection disable behavior detected.'
                Procedure = 'Re-enable Defender real-time and IOAV monitoring immediately and validate current Defender settings.'
            }
        }
        'AddExclusion' {
            return [pscustomobject]@{
                Analysis = 'Defender exclusion changes were detected.'
                Procedure = 'Review Defender exclusions and remove any that are not required for known trusted tooling.'
            }
        }
        'CredentialHarvest' {
            return [pscustomobject]@{
                Analysis = 'Potentially sensitive credential handling pattern found.'
                Procedure = 'Avoid plaintext transformations, rotate exposed credentials, and use secure vault-backed secret retrieval.'
            }
        }
        'ProcessInjection' {
            return [pscustomobject]@{
                Analysis = 'Living-off-the-land execution pattern detected.'
                Procedure = 'Review parent process and source script; remove unneeded elevated execution shortcuts from history.'
            }
        }
        default {
            return [pscustomobject]@{
                Analysis = 'General risky command indicator detected.'
                Procedure = 'Review command context, validate intent, and remove unauthorized command artifacts.'
            }
        }
    }
}

function Remove-RiskyPowerShellHistoryEntries {
    param(
        [Parameter(Mandatory)]
        [string[]]$PatternNames
    )

    $regexByPattern = @{
        'Invoke-Expression' = '(?i)\b(Invoke-Expression|iex)\b'
        'EncodedCommand'    = '(?i)-enc(odedcommand)?\b'
        'DownloadString'    = '(?i)DownloadString\s*\('
        'Invoke-WebRequest' = '(?i)\b(iwr|Invoke-WebRequest)\b'
        'Invoke-RestMethod' = '(?i)\b(irm|Invoke-RestMethod)\b'
        'Net.WebClient'   = '(?i)Net\.WebClient'
        'BypassPolicy'      = '(?i)-ExecutionPolicy\s+Bypass'
        'CredentialHarvest' = '(?i)(Get-Credential|ConvertTo-SecureString\s+.+-AsPlainText)'
        'ProcessInjection'  = '(?i)(Start-Process\s+.+-Verb\s+RunAs|rundll32|regsvr32)'
    }

    $regexList = New-Object System.Collections.Generic.List[string]
    foreach ($name in ($PatternNames | Select-Object -Unique)) {
        if ($regexByPattern.ContainsKey($name)) {
            $regexList.Add($regexByPattern[$name])
        }
    }
    if ($regexList.Count -eq 0) {
        return @('No history cleanup patterns selected.')
    }

    $historyFiles = New-Object System.Collections.Generic.List[string]
    $historyPath = $null
    try {
        if (Get-Command Get-PSReadLineOption -ErrorAction SilentlyContinue) {
            $historyPath = (Get-PSReadLineOption).HistorySavePath
        }
    } catch {}
    if ($historyPath -and (Test-Path $historyPath)) {
        $historyFiles.Add($historyPath)
    }
    $legacyHistory = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if ((Test-Path $legacyHistory) -and (-not $historyFiles.Contains($legacyHistory))) {
        $historyFiles.Add($legacyHistory)
    }

    $messages = New-Object System.Collections.Generic.List[string]
    foreach ($file in $historyFiles) {
        try {
            $lines = Get-Content -Path $file -ErrorAction Stop
            $filtered = New-Object System.Collections.Generic.List[string]
            foreach ($line in $lines) {
                $matchFound = $false
                foreach ($rx in $regexList) {
                    if ($line -match $rx) {
                        $matchFound = $true
                        break
                    }
                }
                if (-not $matchFound) {
                    $filtered.Add($line)
                }
            }

            $removed = $lines.Count - $filtered.Count
            if ($removed -gt 0) {
                $backup = "$file.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
                Copy-Item -Path $file -Destination $backup -Force
                Set-Content -Path $file -Value $filtered -Encoding UTF8
                $messages.Add("History sanitized: removed $removed entries from $file (backup: $backup)")
            } else {
                $messages.Add("No matching risky entries found in $file")
            }
        } catch {
            $messages.Add("Failed history cleanup for $($file): $($_.Exception.Message)")
        }
    }

    if ($historyFiles.Count -eq 0) {
        $messages.Add('No accessible PowerShell history file found for cleanup.')
    }

    return $messages
}

function Invoke-FindingHardeningActions {
    param(
        [Parameter(Mandatory)]
        [object[]]$Findings
    )

    $messages = New-Object System.Collections.Generic.List[string]
    $patternNames = @($Findings | ForEach-Object { $_.Pattern } | Select-Object -Unique)

    $historyPatterns = @(
        'Invoke-Expression','EncodedCommand','DownloadString','Invoke-WebRequest','Invoke-RestMethod',
        'Net.WebClient','BypassPolicy','CredentialHarvest','ProcessInjection'
    )
    $selectedHistoryPatterns = @($patternNames | Where-Object { $_ -in $historyPatterns })
    if ($selectedHistoryPatterns.Count -gt 0) {
        $cleanupMessages = Remove-RiskyPowerShellHistoryEntries -PatternNames $selectedHistoryPatterns
        foreach ($m in $cleanupMessages) { $messages.Add($m) }
    }

    if ($patternNames -contains 'BypassPolicy') {
        try {
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction Stop
            $messages.Add('Execution policy set to RemoteSigned for CurrentUser.')
        } catch {
            $messages.Add("Failed setting execution policy: $($_.Exception.Message)")
        }
    }

    if ($patternNames -contains 'DisableDefender') {
        try {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            Set-MpPreference -DisableIOAVProtection $false -ErrorAction Stop
            $messages.Add('Defender real-time and IOAV monitoring re-enabled.')
        } catch {
            $messages.Add("Failed to re-enable Defender protections: $($_.Exception.Message)")
        }
    }

    if ($patternNames -contains 'AddExclusion') {
        $messages.Add('Manual step required: review Defender exclusions and remove unknown entries with Remove-MpPreference.')
    }

    if ($messages.Count -eq 0) {
        $messages.Add('No automatic hardening action was applicable to the selected finding(s).')
    }

    return $messages
}

function Show-ThreatAnalysisDialog {
    param(
        [object]$Findings = $null
    )

    $inputFindings = @($Findings)
    if (-not $inputFindings -or $inputFindings.Count -eq 0) {
        return
    }

    $normalizedFindings = @(
        $inputFindings | ForEach-Object {
            if ($_ -is [System.Data.DataRowView]) {
                [pscustomobject]@{
                    Severity = [string]$_.Row['Severity']
                    Pattern = [string]$_.Row['Pattern']
                    Source = [string]$_.Row['Source']
                    Location = [string]$_.Row['Location']
                    Evidence = [string]$_.Row['Evidence']
                    Why = [string]$_.Row['Why']
                }
            } else {
                $patternValue = [string]$_.Pattern
                if ([string]::IsNullOrWhiteSpace($patternValue) -and $_ -is [System.Collections.IDictionary] -and $_.Contains('Pattern')) {
                    $patternValue = [string]$_['Pattern']
                }
                [pscustomobject]@{
                    Severity = [string]$_.Severity
                    Pattern = $patternValue
                    Source = [string]$_.Source
                    Location = [string]$_.Location
                    Evidence = [string]$_.Evidence
                    Why = [string]$_.Why
                }
            }
        }
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Pattern) }

    if (-not $normalizedFindings -or $normalizedFindings.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('No valid findings were available for threat analysis.', 'Threat Analysis') | Out-Null
        return
    }

    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = 'Threat Analysis'
    $dialog.Size = New-Object System.Drawing.Size(980, 680)
    $dialog.StartPosition = 'CenterParent'

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = 'Select one or more findings, then click Harden Selected or Harden All.'
    $lbl.AutoSize = $true
    $lbl.Location = New-Object System.Drawing.Point(12, 12)

    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Location = New-Object System.Drawing.Point(12, 38)
    $grid.Size = New-Object System.Drawing.Size(940, 280)
    $grid.Anchor = 'Top,Left,Right'
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.AutoSizeColumnsMode = 'Fill'
    $grid.SelectionMode = 'FullRowSelect'
    $grid.MultiSelect = $true
    $grid.BackgroundColor = [System.Drawing.Color]::White

    $txtAnalysis = New-Object System.Windows.Forms.TextBox
    $txtAnalysis.Location = New-Object System.Drawing.Point(12, 328)
    $txtAnalysis.Size = New-Object System.Drawing.Size(940, 240)
    $txtAnalysis.Anchor = 'Top,Bottom,Left,Right'
    $txtAnalysis.Multiline = $true
    $txtAnalysis.ScrollBars = 'Vertical'
    $txtAnalysis.ReadOnly = $true

    $btnHardenSelected = New-Object System.Windows.Forms.Button
    $btnHardenSelected.Text = 'Harden Selected'
    $btnHardenSelected.Location = New-Object System.Drawing.Point(12, 580)
    $btnHardenSelected.Size = New-Object System.Drawing.Size(130, 30)
    $btnHardenSelected.Anchor = 'Bottom,Left'

    $btnAnalyzeSelected = New-Object System.Windows.Forms.Button
    $btnAnalyzeSelected.Text = 'Analyze Selected'
    $btnAnalyzeSelected.Location = New-Object System.Drawing.Point(150, 580)
    $btnAnalyzeSelected.Size = New-Object System.Drawing.Size(130, 30)
    $btnAnalyzeSelected.Anchor = 'Bottom,Left'

    $btnHardenAll = New-Object System.Windows.Forms.Button
    $btnHardenAll.Text = 'Harden All'
    $btnHardenAll.Location = New-Object System.Drawing.Point(290, 580)
    $btnHardenAll.Size = New-Object System.Drawing.Size(110, 30)
    $btnHardenAll.Anchor = 'Bottom,Left'

    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = 'Close'
    $btnClose.Location = New-Object System.Drawing.Point(842, 580)
    $btnClose.Size = New-Object System.Drawing.Size(110, 30)
    $btnClose.Anchor = 'Bottom,Right'

    [void]$dialog.Controls.Add($lbl)
    [void]$dialog.Controls.Add($grid)
    [void]$dialog.Controls.Add($txtAnalysis)
    [void]$dialog.Controls.Add($btnHardenSelected)
    [void]$dialog.Controls.Add($btnAnalyzeSelected)
    [void]$dialog.Controls.Add($btnHardenAll)
    [void]$dialog.Controls.Add($btnClose)
    Set-GridData -Grid $grid -Rows $normalizedFindings

    $toFinding = {
        param([object]$item)
        if ($null -eq $item) { return $null }
        if ($item -is [System.Data.DataRowView]) {
            return [pscustomobject]@{
                Severity = [string]$item.Row['Severity']
                Pattern = [string]$item.Row['Pattern']
                Source = [string]$item.Row['Source']
                Location = [string]$item.Row['Location']
                Evidence = [string]$item.Row['Evidence']
                Why = [string]$item.Row['Why']
            }
        }
        return [pscustomobject]@{
            Severity = [string]$item.Severity
            Pattern = [string]$item.Pattern
            Source = [string]$item.Source
            Location = [string]$item.Location
            Evidence = [string]$item.Evidence
            Why = [string]$item.Why
        }
    }

    $getSelectedFindings = {
        $selected = @()
        foreach ($row in $grid.SelectedRows) {
            if ($row.DataBoundItem) {
                $finding = & $toFinding $row.DataBoundItem
                if ($finding -and -not [string]::IsNullOrWhiteSpace($finding.Pattern)) {
                    $selected += ,$finding
                }
            }
        }
        if (@($selected).Count -eq 0 -and $grid.CurrentRow -and $grid.CurrentRow.DataBoundItem) {
            $finding = & $toFinding $grid.CurrentRow.DataBoundItem
            if ($finding -and -not [string]::IsNullOrWhiteSpace($finding.Pattern)) {
                $selected += ,$finding
            }
        }
        return @($selected)
    }

    $updateAnalysis = {
        $selected = @(& $getSelectedFindings)
        if (-not $selected -or $selected.Count -eq 0) {
            $txtAnalysis.Text = 'Select a finding to view threat analysis and remediation procedure.'
            return
        }

        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($finding in $selected) {
            $plan = Get-ThreatRemediationPlan -Finding $finding
            $lines.Add("Threat: $($finding.Pattern) [$($finding.Severity)]")
            $lines.Add("Source: $($finding.Source)")
            $lines.Add("Evidence: $($finding.Evidence)")
            $lines.Add("Analysis: $($plan.Analysis)")
            $lines.Add("Procedure: $($plan.Procedure)")
            $lines.Add('')
        }
        $txtAnalysis.Text = ($lines -join [Environment]::NewLine)
    }

    $btnAnalyzeSelected.Add_Click({
        & $updateAnalysis
    })

    $btnHardenSelected.Add_Click({
        $target = & $getSelectedFindings
        if (-not $target -or $target.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show('Select at least one finding first.', 'Threat Analysis') | Out-Null
            return
        }
        $result = Invoke-FindingHardeningActions -Findings $target
        [System.Windows.Forms.MessageBox]::Show(($result -join [Environment]::NewLine), 'Harden Selected Results') | Out-Null
    })

    $btnHardenAll.Add_Click({
        $result = Invoke-FindingHardeningActions -Findings $normalizedFindings
        [System.Windows.Forms.MessageBox]::Show(($result -join [Environment]::NewLine), 'Harden All Results') | Out-Null
    })

    $btnClose.Add_Click({ $dialog.Close() })

    if ($grid.Rows.Count -gt 0) {
        $grid.Rows[0].Selected = $true
    }
    & $updateAnalysis

    [void]$dialog.ShowDialog()
}

function Add-InboundBlockRule {
    param(
        [Parameter(Mandatory)]
        [int]$Port
    )

    $ruleName = Get-PortBlockRuleName -Port $Port
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) {
        return "Rule already exists: $ruleName"
    }

    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Block -Enabled True -Protocol TCP -LocalPort $Port -Profile Any | Out-Null
    return "Blocked inbound TCP port $Port (rule: $ruleName)"
}

function Get-PortBlockRuleName {
    param(
        [Parameter(Mandatory)]
        [int]$Port
    )
    return "HardeningBlock_In_$Port"
}

function Remove-InboundBlockRule {
    param(
        [Parameter(Mandatory)]
        [int]$Port
    )

    $ruleName = Get-PortBlockRuleName -Port $Port
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        return "No block rule found for TCP port $Port."
    }

    $existing | Remove-NetFirewallRule -ErrorAction Stop
    return "Unblocked inbound TCP port $Port (removed rule: $ruleName)"
}

function Test-InboundBlockRuleExists {
    param(
        [Parameter(Mandatory)]
        [int]$Port
    )
    $ruleName = Get-PortBlockRuleName -Port $Port
    return [bool](Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)
}

function Get-HighRiskExternalPortCatalog {
    # Curated commonly abused/targeted externally exposed service ports.
    return @(
        [pscustomobject]@{ Port = 20; Service = 'FTP Data'; Reason = 'Legacy file transfer protocol commonly brute-forced or abused.' }
        [pscustomobject]@{ Port = 21; Service = 'FTP Control'; Reason = 'Legacy cleartext auth channel; high external abuse.' }
        [pscustomobject]@{ Port = 22; Service = 'SSH'; Reason = 'Frequent internet brute-force target.' }
        [pscustomobject]@{ Port = 23; Service = 'Telnet'; Reason = 'Cleartext remote admin and high exploitation risk.' }
        [pscustomobject]@{ Port = 25; Service = 'SMTP'; Reason = 'Open relays/misconfig abuse and spam infrastructure target.' }
        [pscustomobject]@{ Port = 53; Service = 'DNS'; Reason = 'Can be abused for reflection/amplification and data exfil paths.' }
        [pscustomobject]@{ Port = 69; Service = 'TFTP'; Reason = 'Unauthenticated file transfer commonly abused on edge devices.' }
        [pscustomobject]@{ Port = 80; Service = 'HTTP'; Reason = 'Web attack surface and exploit scanning target.' }
        [pscustomobject]@{ Port = 110; Service = 'POP3'; Reason = 'Legacy mail protocol, often weakly protected.' }
        [pscustomobject]@{ Port = 111; Service = 'RPCbind'; Reason = 'Service enumeration and legacy RPC exposure.' }
        [pscustomobject]@{ Port = 135; Service = 'RPC Endpoint Mapper'; Reason = 'Frequent lateral movement and remote service abuse vector.' }
        [pscustomobject]@{ Port = 137; Service = 'NetBIOS Name'; Reason = 'Legacy NetBIOS exposure, often unnecessary externally.' }
        [pscustomobject]@{ Port = 138; Service = 'NetBIOS Datagram'; Reason = 'Legacy NetBIOS exposure, often unnecessary externally.' }
        [pscustomobject]@{ Port = 139; Service = 'NetBIOS Session'; Reason = 'Legacy SMB/NetBIOS exposure and credential attack path.' }
        [pscustomobject]@{ Port = 143; Service = 'IMAP'; Reason = 'Legacy mail protocol, frequently brute-forced.' }
        [pscustomobject]@{ Port = 389; Service = 'LDAP'; Reason = 'Directory service exposure and credential reconnaissance risk.' }
        [pscustomobject]@{ Port = 443; Service = 'HTTPS'; Reason = 'Public web/API attack surface.' }
        [pscustomobject]@{ Port = 445; Service = 'SMB'; Reason = 'Historically high-impact worm/ransomware propagation vector.' }
        [pscustomobject]@{ Port = 636; Service = 'LDAPS'; Reason = 'Directory exposure risk if internet-facing.' }
        [pscustomobject]@{ Port = 1433; Service = 'MSSQL'; Reason = 'Database service frequently scanned and brute-forced.' }
        [pscustomobject]@{ Port = 1434; Service = 'MSSQL Browser'; Reason = 'Database discovery target.' }
        [pscustomobject]@{ Port = 1521; Service = 'Oracle DB'; Reason = 'Common enterprise DB target when exposed.' }
        [pscustomobject]@{ Port = 3306; Service = 'MySQL'; Reason = 'Database service frequently targeted externally.' }
        [pscustomobject]@{ Port = 3389; Service = 'RDP'; Reason = 'Major ransomware initial-access vector when internet-exposed.' }
        [pscustomobject]@{ Port = 5432; Service = 'PostgreSQL'; Reason = 'Database target when exposed to untrusted networks.' }
        [pscustomobject]@{ Port = 5500; Service = 'VNC/Remote'; Reason = 'Remote access service frequently abused if exposed.' }
        [pscustomobject]@{ Port = 5601; Service = 'Kibana'; Reason = 'Commonly scanned admin interface port.' }
        [pscustomobject]@{ Port = 5900; Service = 'VNC'; Reason = 'Remote desktop protocol frequently brute-forced.' }
        [pscustomobject]@{ Port = 5985; Service = 'WinRM HTTP'; Reason = 'Remote administration surface for lateral movement.' }
        [pscustomobject]@{ Port = 5986; Service = 'WinRM HTTPS'; Reason = 'Remote administration surface for lateral movement.' }
        [pscustomobject]@{ Port = 6379; Service = 'Redis'; Reason = 'Historically exposed Redis instances are frequently abused.' }
        [pscustomobject]@{ Port = 8080; Service = 'HTTP Alt/Proxy'; Reason = 'Frequent target for app/proxy exploitation.' }
        [pscustomobject]@{ Port = 8443; Service = 'HTTPS Alt/Admin'; Reason = 'Common admin/API surface port.' }
        [pscustomobject]@{ Port = 9200; Service = 'Elasticsearch'; Reason = 'Frequent unauthorized data exposure target.' }
        [pscustomobject]@{ Port = 9300; Service = 'Elasticsearch Transport'; Reason = 'Cluster interface exposure risk.' }
        [pscustomobject]@{ Port = 27017; Service = 'MongoDB'; Reason = 'Historically high-profile exposed database target.' }
    ) | Sort-Object Port -Unique
}

function Update-PortGridVirtualScrollBars {
    param(
        [Parameter(Mandatory)]
        [System.Windows.Forms.DataGridView]$Grid,
        [Parameter(Mandatory)]
        [System.Windows.Forms.VScrollBar]$VBar,
        [Parameter(Mandatory)]
        [System.Windows.Forms.HScrollBar]$HBar
    )
    Update-AuditVirtualScrollBars -Grid $Grid -VBar $VBar -HBar $HBar
}

function Scroll-PortGridBy {
    param(
        [Parameter(Mandatory)]
        [System.Windows.Forms.DataGridView]$Grid,
        [Parameter(Mandatory)]
        [System.Windows.Forms.VScrollBar]$VBar,
        [Parameter(Mandatory)]
        [System.Windows.Forms.HScrollBar]$HBar,
        [Parameter(Mandatory)]
        [int]$DeltaRows
    )

    if ($Grid.RowCount -le 0) { return }
    $maxRowIndex = $Grid.RowCount - 1
    $current = 0
    try { $current = $Grid.FirstDisplayedScrollingRowIndex } catch { $current = 0 }
    if ($current -lt 0) { $current = 0 }
    $target = [Math]::Max(0, [Math]::Min($maxRowIndex, $current + $DeltaRows))
    try { $Grid.FirstDisplayedScrollingRowIndex = $target } catch {}
    Update-PortGridVirtualScrollBars -Grid $Grid -VBar $VBar -HBar $HBar
}

function Get-HardeningRecommendations {
    param(
        [Parameter(Mandatory)]
        [object[]]$Findings,
        [Parameter(Mandatory)]
        [int[]]$ListeningPorts,
        [object[]]$PortDetails = @(),
        [object]$Context = $null
    )

    $recommendations = New-Object System.Collections.Generic.List[object]
    $priorityRank = @{ High = 0; Medium = 1; Low = 2 }
    $severityCounts = @{
        Critical = ($Findings | Where-Object Severity -eq 'Critical').Count
        High = ($Findings | Where-Object Severity -eq 'High').Count
        Medium = ($Findings | Where-Object Severity -eq 'Medium').Count
    }

    if ($severityCounts.Critical -gt 0) {
        $recommendations.Add([pscustomobject]@{
            Priority = 'High'
            Area = 'PowerShell'
            Item = 'Critical command patterns detected'
            Recommendation = 'Review evidence and remove unsafe scripts or one-liners immediately.'
            Why = "Detected $($severityCounts.Critical) critical events."
        })
    }

    if ($severityCounts.High -gt 0) {
        $recommendations.Add([pscustomobject]@{
            Priority = 'High'
            Area = 'PowerShell'
            Item = 'High-risk command patterns detected'
            Recommendation = 'Replace risky patterns with signed scripts and constrained execution.'
            Why = "Detected $($severityCounts.High) high-severity events."
        })
    }

    if (($Findings | Where-Object Pattern -eq 'EncodedCommand').Count -gt 0) {
        $recommendations.Add([pscustomobject]@{
            Priority = 'High'
            Area = 'PowerShell'
            Item = 'EncodedCommand usage found'
            Recommendation = 'Investigate each encoded command; keep only known admin automation.'
            Why = 'Encoded commands are commonly used to hide malicious activity.'
        })
    }

    if (($Findings | Where-Object Pattern -eq 'BypassPolicy').Count -gt 0) {
        $recommendations.Add([pscustomobject]@{
            Priority = 'High'
            Area = 'PowerShell'
            Item = 'ExecutionPolicy bypass usage found'
            Recommendation = 'Enforce stronger policy (RemoteSigned/AllSigned) and remove bypass shortcuts.'
            Why = 'Bypass mode weakens script execution controls.'
        })
    }

    if (($Findings | Where-Object Pattern -in @('DisableDefender','AddExclusion')).Count -gt 0) {
        $recommendations.Add([pscustomobject]@{
            Priority = 'High'
            Area = 'Defender'
            Item = 'Defender tamper-like commands detected'
            Recommendation = 'Audit and revert unneeded Defender preference changes.'
            Why = 'Disabling protections or adding exclusions increases malware exposure.'
        })
    }

    $portGuidance = @{
        22   = @{ Label = 'SSH'; Recommendation = 'Block if not actively used for remote administration.'; Priority = 'High' }
        23   = @{ Label = 'Telnet'; Recommendation = 'Block; legacy plaintext protocol should stay closed.'; Priority = 'High' }
        80   = @{ Label = 'HTTP'; Recommendation = 'Keep only if hosting services; otherwise block.'; Priority = 'Medium' }
        135  = @{ Label = 'RPC Endpoint Mapper'; Recommendation = 'Keep restricted to trusted networks only.'; Priority = 'High' }
        139  = @{ Label = 'NetBIOS Session'; Recommendation = 'Block on modern endpoints unless legacy dependency exists.'; Priority = 'High' }
        443  = @{ Label = 'HTTPS'; Recommendation = 'Keep only for required services; otherwise block.'; Priority = 'Medium' }
        445  = @{ Label = 'SMB'; Recommendation = 'Block from untrusted networks and internet-facing paths.'; Priority = 'High' }
        3389 = @{ Label = 'RDP'; Recommendation = 'Block unless required; if required, restrict source IPs + MFA/VPN.'; Priority = 'High' }
        5985 = @{ Label = 'WinRM HTTP'; Recommendation = 'Disable or restrict to management subnet only.'; Priority = 'High' }
        5986 = @{ Label = 'WinRM HTTPS'; Recommendation = 'Restrict to trusted admin hosts only.'; Priority = 'High' }
    }

    foreach ($port in $ListeningPorts | Sort-Object -Unique) {
        $bindings = @($PortDetails | Where-Object Port -eq $port)
        $publicBinding = ($bindings | Where-Object PublicFacing).Count -gt 0
        $addrNote = if ($bindings.Count -gt 0) { ($bindings | Select-Object -First 2 | ForEach-Object { $_.Address } | Sort-Object -Unique) -join ',' } else { 'unknown' }
        if ($portGuidance.ContainsKey($port)) {
            $guide = $portGuidance[$port]
            $dynamicPriority = $guide.Priority
            if ($publicBinding -and $dynamicPriority -eq 'Medium') { $dynamicPriority = 'High' }
            $recommendations.Add([pscustomobject]@{
                Priority = $dynamicPriority
                Area = 'Port'
                Item = "$port ($($guide.Label)) is listening"
                Recommendation = $guide.Recommendation
                Why = "Known high-value service port. Binding: $addrNote"
            })
        } elseif ($port -lt 1024) {
            $p = if ($publicBinding) { 'High' } else { 'Medium' }
            $recommendations.Add([pscustomobject]@{
                Priority = $p
                Area = 'Port'
                Item = "$port is listening"
                Recommendation = 'Validate owning service; block if unnecessary.'
                Why = "Well-known system/service port. Binding: $addrNote"
            })
        } else {
            $recommendations.Add([pscustomobject]@{
                Priority = 'Low'
                Area = 'Port'
                Item = "$port is listening"
                Recommendation = 'Confirm expected application is bound and limited to required interfaces.'
                Why = "Non-well-known port may still expand attack surface. Binding: $addrNote"
            })
        }
    }

    if ($recommendations.Count -eq 0) {
        $recommendations.Add([pscustomobject]@{
            Priority = 'Low'
            Area = 'General'
            Item = 'No immediate risky indicators found'
            Recommendation = 'Keep logging enabled and rerun scans after major config changes.'
            Why = 'No matching risky patterns or listening ports were returned.'
        })
    }

    return $recommendations |
        Sort-Object @{Expression = { $priorityRank[$_.Priority] }}, Area, Item |
        Select-Object Priority, Area, Item, Recommendation, Why
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'PowerShell Hardening Dashboard'
$form.Size = New-Object System.Drawing.Size(1150, 760)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 8.0)

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'

$tabAudit = New-Object System.Windows.Forms.TabPage
$tabAudit.Text = 'PowerShell Audit'

$tabPorts = New-Object System.Windows.Forms.TabPage
$tabPorts.Text = 'Port Lockdown'

$tabRecommendations = New-Object System.Windows.Forms.TabPage
$tabRecommendations.Text = 'Recommendations'

$auditInfo = New-Object System.Windows.Forms.Label
$auditInfo.Text = 'Scans PowerShell history, transcript files, and event logs for risky command patterns.'
$auditInfo.AutoSize = $true
$auditInfo.Location = New-Object System.Drawing.Point(12, 12)

$btnScan = New-Object System.Windows.Forms.Button
$btnScan.Text = 'Run Audit Scan'
$btnScan.Location = New-Object System.Drawing.Point(12, 40)
$btnScan.Size = New-Object System.Drawing.Size(130, 30)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text = 'Export CSV'
$btnExport.Location = New-Object System.Drawing.Point(150, 40)
$btnExport.Size = New-Object System.Drawing.Size(100, 30)

$btnThreatAnalysis = New-Object System.Windows.Forms.Button
$btnThreatAnalysis.Text = 'Threat Analysis'
$btnThreatAnalysis.Location = New-Object System.Drawing.Point(258, 40)
$btnThreatAnalysis.Size = New-Object System.Drawing.Size(120, 30)

$lblAuditStatus = New-Object System.Windows.Forms.Label
$lblAuditStatus.Text = 'Status: waiting for scan.'
$lblAuditStatus.AutoSize = $true
$lblAuditStatus.Location = New-Object System.Drawing.Point(390, 47)

$lblZoom = New-Object System.Windows.Forms.Label
$lblZoom.Text = 'Zoom'
$lblZoom.AutoSize = $true
$lblZoom.Location = New-Object System.Drawing.Point(760, 46)

$trackZoom = New-Object System.Windows.Forms.TrackBar
$trackZoom.Location = New-Object System.Drawing.Point(800, 38)
$trackZoom.Size = New-Object System.Drawing.Size(220, 36)
$trackZoom.Minimum = 70
$trackZoom.Maximum = 140
$trackZoom.TickFrequency = 10
$trackZoom.SmallChange = 5
$trackZoom.LargeChange = 10
$trackZoom.Value = 100

$lblZoomValue = New-Object System.Windows.Forms.Label
$lblZoomValue.Text = '100%'
$lblZoomValue.AutoSize = $true
$lblZoomValue.Location = New-Object System.Drawing.Point(1028, 46)

$gridAudit = New-Object System.Windows.Forms.DataGridView
$gridAudit.Location = New-Object System.Drawing.Point(38, 106)
$gridAudit.Size = New-Object System.Drawing.Size(1048, 536)
$gridAudit.Anchor = 'Top,Bottom,Left,Right'
$gridAudit.AutoSizeColumnsMode = 'None'
$gridAudit.ScrollBars = 'None'
$gridAudit.ReadOnly = $true
$gridAudit.AllowUserToAddRows = $false
$gridAudit.AllowUserToDeleteRows = $false
$gridAudit.AllowUserToResizeColumns = $true
$gridAudit.AllowUserToResizeRows = $true
$gridAudit.RowHeadersVisible = $true
$gridAudit.RowHeadersWidth = 28
$gridAudit.SelectionMode = 'FullRowSelect'
$gridAudit.MultiSelect = $true
$gridAudit.BackgroundColor = [System.Drawing.Color]::White
$gridAudit.GridColor = [System.Drawing.Color]::LightGray
$gridAudit.EnableHeadersVisualStyles = $false
$gridAudit.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::Gainsboro
$gridAudit.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
$gridAudit.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
$gridAudit.DefaultCellStyle.BackColor = [System.Drawing.Color]::White

$vScrollAudit = New-Object System.Windows.Forms.VScrollBar
$vScrollAudit.Location = New-Object System.Drawing.Point(12, 106)
$vScrollAudit.Size = New-Object System.Drawing.Size(12, 536)
$vScrollAudit.Anchor = 'Top,Bottom,Left'
$vScrollAudit.Enabled = $true
$vScrollAudit.Visible = $true
$vScrollAudit.Minimum = 0
$vScrollAudit.Maximum = 1
$vScrollAudit.LargeChange = 1
$vScrollAudit.SmallChange = 1

$hScrollAudit = New-Object System.Windows.Forms.HScrollBar
$hScrollAudit.Location = New-Object System.Drawing.Point(38, 82)
$hScrollAudit.Size = New-Object System.Drawing.Size(1048, 12)
$hScrollAudit.Anchor = 'Top,Left,Right'
$hScrollAudit.Enabled = $true
$hScrollAudit.Visible = $true
$hScrollAudit.Minimum = 0
$hScrollAudit.Maximum = 1
$hScrollAudit.LargeChange = 1
$hScrollAudit.SmallChange = 1

$tabAudit.Controls.AddRange(@($auditInfo, $btnScan, $btnExport, $btnThreatAnalysis, $lblAuditStatus, $lblZoom, $trackZoom, $lblZoomValue, $gridAudit, $vScrollAudit, $hScrollAudit))

$portInfo = New-Object System.Windows.Forms.Label
$portInfo.Text = 'Review listening and high-risk external TCP ports. Create or remove inbound firewall block rules.'
$portInfo.AutoSize = $true
$portInfo.Location = New-Object System.Drawing.Point(12, 12)

$btnRefreshPorts = New-Object System.Windows.Forms.Button
$btnRefreshPorts.Text = 'Refresh Ports'
$btnRefreshPorts.Location = New-Object System.Drawing.Point(12, 40)
$btnRefreshPorts.Size = New-Object System.Drawing.Size(110, 30)

$btnBlockSelected = New-Object System.Windows.Forms.Button
$btnBlockSelected.Text = 'Block Selected'
$btnBlockSelected.Location = New-Object System.Drawing.Point(130, 40)
$btnBlockSelected.Size = New-Object System.Drawing.Size(120, 30)

$btnUnblockSelected = New-Object System.Windows.Forms.Button
$btnUnblockSelected.Text = 'Unblock Selected'
$btnUnblockSelected.Location = New-Object System.Drawing.Point(258, 40)
$btnUnblockSelected.Size = New-Object System.Drawing.Size(120, 30)

$txtCustomPort = New-Object System.Windows.Forms.TextBox
$txtCustomPort.Location = New-Object System.Drawing.Point(390, 45)
$txtCustomPort.Size = New-Object System.Drawing.Size(90, 23)

$btnBlockCustom = New-Object System.Windows.Forms.Button
$btnBlockCustom.Text = 'Block Port'
$btnBlockCustom.Location = New-Object System.Drawing.Point(490, 40)
$btnBlockCustom.Size = New-Object System.Drawing.Size(90, 30)

$btnUnblockCustom = New-Object System.Windows.Forms.Button
$btnUnblockCustom.Text = 'Unblock Port'
$btnUnblockCustom.Location = New-Object System.Drawing.Point(588, 40)
$btnUnblockCustom.Size = New-Object System.Drawing.Size(95, 30)

$gridPorts = New-Object System.Windows.Forms.DataGridView
$gridPorts.Location = New-Object System.Drawing.Point(28, 24)
$gridPorts.Size = New-Object System.Drawing.Size(404, 504)
$gridPorts.Anchor = 'Top,Bottom,Left,Right'
$gridPorts.AutoSizeColumnsMode = 'None'
$gridPorts.ScrollBars = 'None'
$gridPorts.ReadOnly = $true
$gridPorts.AllowUserToAddRows = $false
$gridPorts.AllowUserToDeleteRows = $false
$gridPorts.AllowUserToResizeColumns = $true
$gridPorts.AllowUserToResizeRows = $false
$gridPorts.RowHeadersVisible = $true
$gridPorts.RowHeadersWidth = 24
$gridPorts.SelectionMode = 'FullRowSelect'
$gridPorts.MultiSelect = $true
$gridPorts.BackgroundColor = [System.Drawing.Color]::White
$gridPorts.GridColor = [System.Drawing.Color]::LightGray
$gridPorts.EnableHeadersVisualStyles = $false
$gridPorts.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::Gainsboro
$gridPorts.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
$gridPorts.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
$gridPorts.DefaultCellStyle.BackColor = [System.Drawing.Color]::White

$vScrollPorts = New-Object System.Windows.Forms.VScrollBar
$vScrollPorts.Location = New-Object System.Drawing.Point(4, 24)
$vScrollPorts.Size = New-Object System.Drawing.Size(12, 504)
$vScrollPorts.Anchor = 'Top,Bottom,Left'
$vScrollPorts.Minimum = 0
$vScrollPorts.Maximum = 1
$vScrollPorts.LargeChange = 1
$vScrollPorts.SmallChange = 1
$vScrollPorts.Enabled = $true
$vScrollPorts.Visible = $true

$hScrollPorts = New-Object System.Windows.Forms.HScrollBar
$hScrollPorts.Location = New-Object System.Drawing.Point(28, 4)
$hScrollPorts.Size = New-Object System.Drawing.Size(404, 12)
$hScrollPorts.Anchor = 'Top,Left,Right'
$hScrollPorts.Minimum = 0
$hScrollPorts.Maximum = 1
$hScrollPorts.LargeChange = 1
$hScrollPorts.SmallChange = 1
$hScrollPorts.Enabled = $true
$hScrollPorts.Visible = $true

$txtPortSummary = New-Object System.Windows.Forms.TextBox
$txtPortSummary.Location = New-Object System.Drawing.Point(8, 82)
$txtPortSummary.Size = New-Object System.Drawing.Size(438, 56)
$txtPortSummary.Multiline = $true
$txtPortSummary.ReadOnly = $true
$txtPortSummary.ScrollBars = 'Vertical'
$txtPortSummary.Text = 'Port summary will appear here.'

$txtPortDetails = New-Object System.Windows.Forms.TextBox
$txtPortDetails.Location = New-Object System.Drawing.Point(446, 82)
$txtPortDetails.Size = New-Object System.Drawing.Size(666, 56)
$txtPortDetails.Anchor = 'Top,Left,Right'
$txtPortDetails.Multiline = $true
$txtPortDetails.ReadOnly = $true
$txtPortDetails.ScrollBars = 'Vertical'
$txtPortDetails.Text = 'Select a port row to view details.'

$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Location = New-Object System.Drawing.Point(446, 146)
$txtOutput.Size = New-Object System.Drawing.Size(666, 536)
$txtOutput.Anchor = 'Top,Bottom,Left,Right'
$txtOutput.Multiline = $true
$txtOutput.ScrollBars = 'Both'
$txtOutput.WordWrap = $false
$txtOutput.ReadOnly = $true

$panelPortsViewport = New-Object System.Windows.Forms.Panel
$panelPortsViewport.Location = New-Object System.Drawing.Point(8, 146)
$panelPortsViewport.Size = New-Object System.Drawing.Size(438, 536)
$panelPortsViewport.Anchor = 'Top,Bottom,Left'
$panelPortsViewport.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

$panelPortsViewport.Controls.AddRange(@($hScrollPorts, $gridPorts, $vScrollPorts))
$vScrollPorts.BringToFront()

$tabPorts.Controls.AddRange(@($portInfo, $btnRefreshPorts, $btnBlockSelected, $btnUnblockSelected, $txtCustomPort, $btnBlockCustom, $btnUnblockCustom, $txtPortSummary, $txtPortDetails, $panelPortsViewport, $txtOutput))

$recInfo = New-Object System.Windows.Forms.Label
$recInfo.Text = 'Prioritized hardening guidance based on your findings and listening ports.'
$recInfo.AutoSize = $true
$recInfo.Location = New-Object System.Drawing.Point(12, 12)

$btnGenerateReco = New-Object System.Windows.Forms.Button
$btnGenerateReco.Text = 'Generate Recommendations'
$btnGenerateReco.Location = New-Object System.Drawing.Point(12, 40)
$btnGenerateReco.Size = New-Object System.Drawing.Size(200, 30)

$btnExportRecoCsv = New-Object System.Windows.Forms.Button
$btnExportRecoCsv.Text = 'Export CSV Report'
$btnExportRecoCsv.Location = New-Object System.Drawing.Point(220, 40)
$btnExportRecoCsv.Size = New-Object System.Drawing.Size(130, 30)

$lblScoreTitle = New-Object System.Windows.Forms.Label
$lblScoreTitle.Text = 'Security Posture Score: -- / 100'
$lblScoreTitle.AutoSize = $true
$lblScoreTitle.Location = New-Object System.Drawing.Point(360, 45)

$lblRiskLevel = New-Object System.Windows.Forms.Label
$lblRiskLevel.Text = 'Risk Level: --'
$lblRiskLevel.AutoSize = $true
$lblRiskLevel.Location = New-Object System.Drawing.Point(430, 45)

$txtTopDrivers = New-Object System.Windows.Forms.TextBox
$txtTopDrivers.Location = New-Object System.Drawing.Point(12, 82)
$txtTopDrivers.Size = New-Object System.Drawing.Size(560, 56)
$txtTopDrivers.Multiline = $true
$txtTopDrivers.ReadOnly = $true
$txtTopDrivers.ScrollBars = 'Vertical'
$txtTopDrivers.Text = 'Top 3 Risk Drivers will appear here.'

$txtBehaviorAlerts = New-Object System.Windows.Forms.TextBox
$txtBehaviorAlerts.Location = New-Object System.Drawing.Point(580, 82)
$txtBehaviorAlerts.Size = New-Object System.Drawing.Size(532, 56)
$txtBehaviorAlerts.Multiline = $true
$txtBehaviorAlerts.ReadOnly = $true
$txtBehaviorAlerts.ScrollBars = 'Vertical'
$txtBehaviorAlerts.Text = 'Attack pattern correlation alerts will appear here.'

$lblFix = New-Object System.Windows.Forms.Label
$lblFix.Text = 'Fix It'
$lblFix.AutoSize = $true
$lblFix.Location = New-Object System.Drawing.Point(12, 146)

$cmbFixes = New-Object System.Windows.Forms.ComboBox
$cmbFixes.Location = New-Object System.Drawing.Point(52, 142)
$cmbFixes.Size = New-Object System.Drawing.Size(300, 24)
$cmbFixes.DropDownStyle = 'DropDownList'
[void]$cmbFixes.Items.AddRange(@(
    'restrict_smb_private | Restrict SMB to Public-Blocked',
    'enforce_allsigned | Enforce AllSigned ExecutionPolicy',
    'reenable_defender | Re-enable Defender Protection'
))
$cmbFixes.SelectedIndex = 0

$btnPreviewFix = New-Object System.Windows.Forms.Button
$btnPreviewFix.Text = 'Preview Fix'
$btnPreviewFix.Location = New-Object System.Drawing.Point(360, 140)
$btnPreviewFix.Size = New-Object System.Drawing.Size(100, 28)

$btnApplyFix = New-Object System.Windows.Forms.Button
$btnApplyFix.Text = 'Apply Fix'
$btnApplyFix.Location = New-Object System.Drawing.Point(466, 140)
$btnApplyFix.Size = New-Object System.Drawing.Size(90, 28)

$btnRollbackFix = New-Object System.Windows.Forms.Button
$btnRollbackFix.Text = 'Rollback'
$btnRollbackFix.Location = New-Object System.Drawing.Point(562, 140)
$btnRollbackFix.Size = New-Object System.Drawing.Size(90, 28)

$txtFixOutput = New-Object System.Windows.Forms.TextBox
$txtFixOutput.Location = New-Object System.Drawing.Point(658, 142)
$txtFixOutput.Size = New-Object System.Drawing.Size(454, 24)
$txtFixOutput.ReadOnly = $true

$lblRecoZoom = New-Object System.Windows.Forms.Label
$lblRecoZoom.Text = 'Zoom'
$lblRecoZoom.AutoSize = $true
$lblRecoZoom.Location = New-Object System.Drawing.Point(760, 46)

$trackRecoZoom = New-Object System.Windows.Forms.TrackBar
$trackRecoZoom.Location = New-Object System.Drawing.Point(800, 38)
$trackRecoZoom.Size = New-Object System.Drawing.Size(220, 36)
$trackRecoZoom.Minimum = 70
$trackRecoZoom.Maximum = 140
$trackRecoZoom.TickFrequency = 10
$trackRecoZoom.SmallChange = 5
$trackRecoZoom.LargeChange = 10
$trackRecoZoom.Value = 100

$lblRecoZoomValue = New-Object System.Windows.Forms.Label
$lblRecoZoomValue.Text = '100%'
$lblRecoZoomValue.AutoSize = $true
$lblRecoZoomValue.Location = New-Object System.Drawing.Point(1028, 46)

$gridReco = New-Object System.Windows.Forms.DataGridView
$gridReco.Location = New-Object System.Drawing.Point(38, 192)
$gridReco.Size = New-Object System.Drawing.Size(1048, 450)
$gridReco.Anchor = 'Top,Bottom,Left,Right'
$gridReco.AutoSizeColumnsMode = 'None'
$gridReco.ScrollBars = 'None'
$gridReco.ReadOnly = $true
$gridReco.AllowUserToAddRows = $false
$gridReco.AllowUserToDeleteRows = $false
$gridReco.AllowUserToResizeColumns = $true
$gridReco.AllowUserToResizeRows = $true
$gridReco.RowHeadersVisible = $true
$gridReco.RowHeadersWidth = 28
$gridReco.BackgroundColor = [System.Drawing.Color]::White
$gridReco.GridColor = [System.Drawing.Color]::LightGray
$gridReco.EnableHeadersVisualStyles = $false
$gridReco.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::Gainsboro
$gridReco.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
$gridReco.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
$gridReco.DefaultCellStyle.BackColor = [System.Drawing.Color]::White

$vScrollReco = New-Object System.Windows.Forms.VScrollBar
$vScrollReco.Location = New-Object System.Drawing.Point(12, 106)
$vScrollReco.Size = New-Object System.Drawing.Size(12, 536)
$vScrollReco.Anchor = 'Top,Bottom,Left'
$vScrollReco.Enabled = $true
$vScrollReco.Visible = $true
$vScrollReco.Minimum = 0
$vScrollReco.Maximum = 1
$vScrollReco.LargeChange = 1
$vScrollReco.SmallChange = 1

$hScrollReco = New-Object System.Windows.Forms.HScrollBar
$hScrollReco.Location = New-Object System.Drawing.Point(38, 176)
$hScrollReco.Size = New-Object System.Drawing.Size(1048, 12)
$hScrollReco.Anchor = 'Top,Left,Right'
$hScrollReco.Enabled = $true
$hScrollReco.Visible = $true
$hScrollReco.Minimum = 0
$hScrollReco.Maximum = 1
$hScrollReco.LargeChange = 1
$hScrollReco.SmallChange = 1

$tabRecommendations.Controls.AddRange(@($recInfo, $btnGenerateReco, $btnExportRecoCsv, $lblScoreTitle, $lblRiskLevel, $txtTopDrivers, $txtBehaviorAlerts, $lblFix, $cmbFixes, $btnPreviewFix, $btnApplyFix, $btnRollbackFix, $txtFixOutput, $lblRecoZoom, $trackRecoZoom, $lblRecoZoomValue, $gridReco, $vScrollReco, $hScrollReco))

$tabs.TabPages.AddRange(@($tabAudit, $tabPorts, $tabRecommendations))
$form.Controls.Add($tabs)

$script:lastFindings = @()
$script:lastPorts = @()
$script:lastPortDetails = @()
$script:lastContext = $null
$script:rollbackJournal = @{}
$script:lastSummary = $null
$script:lastRecommendations = @()
$script:lastAlerts = @()
$script:baselineSummary = $null
$script:auditZoomPercent = 100
$script:recoZoomPercent = 100
$script:recoViewportTop = 176
$script:auditScrollThickness = Get-ScrollThicknessFromZoom -Percent $script:auditZoomPercent
Layout-AuditViewport -Tab $tabAudit -Grid $gridAudit -VBar $vScrollAudit -HBar $hScrollAudit -Thickness $script:auditScrollThickness
$script:recoScrollThickness = Get-ScrollThicknessFromZoom -Percent $script:recoZoomPercent
Layout-AuditViewport -Tab $tabRecommendations -Grid $gridReco -VBar $vScrollReco -HBar $hScrollReco -Thickness $script:recoScrollThickness -TopScrollY $script:recoViewportTop

$vScrollAudit.Add_ValueChanged({
    param($sender, $eventArgs)
    if ($gridAudit.RowCount -le 0) { return }
    $maxRowIndex = $gridAudit.RowCount - 1
    $target = [Math]::Max(0, [Math]::Min($maxRowIndex, $vScrollAudit.Value))
    try { $gridAudit.FirstDisplayedScrollingRowIndex = $target } catch {}
})

$hScrollAudit.Add_ValueChanged({
    param($sender, $eventArgs)
    try { $gridAudit.HorizontalScrollingOffset = $hScrollAudit.Value } catch {}
})

$vScrollReco.Add_ValueChanged({
    param($sender, $eventArgs)
    if ($gridReco.RowCount -le 0) { return }
    $maxRowIndex = $gridReco.RowCount - 1
    $target = [Math]::Max(0, [Math]::Min($maxRowIndex, $vScrollReco.Value))
    try { $gridReco.FirstDisplayedScrollingRowIndex = $target } catch {}
})

$hScrollReco.Add_ValueChanged({
    param($sender, $eventArgs)
    try { $gridReco.HorizontalScrollingOffset = $hScrollReco.Value } catch {}
})

$vScrollPorts.Add_ValueChanged({
    param($sender, $eventArgs)
    if ($gridPorts.RowCount -le 0) { return }
    $maxTop = [Math]::Max(0, $gridPorts.RowCount - 1)
    $target = [Math]::Max(0, [Math]::Min($maxTop, $vScrollPorts.Value))
    try { $gridPorts.FirstDisplayedScrollingRowIndex = $target } catch {}
})

$vScrollPorts.Add_Scroll({
    param($sender, $eventArgs)
    if ($gridPorts.RowCount -le 0) { return }
    $maxTop = [Math]::Max(0, $gridPorts.RowCount - 1)
    $target = [Math]::Max(0, [Math]::Min($maxTop, $vScrollPorts.Value))
    try { $gridPorts.FirstDisplayedScrollingRowIndex = $target } catch {}
})

$hScrollPorts.Add_ValueChanged({
    param($sender, $eventArgs)
    try { $gridPorts.HorizontalScrollingOffset = $hScrollPorts.Value } catch {}
})

$gridPorts.Add_Scroll({
    param($sender, $eventArgs)
    Update-PortGridVirtualScrollBars -Grid $gridPorts -VBar $vScrollPorts -HBar $hScrollPorts
})

$gridPorts.Add_DataBindingComplete({
    param($sender, $eventArgs)
    Update-PortGridVirtualScrollBars -Grid $gridPorts -VBar $vScrollPorts -HBar $hScrollPorts
})

$gridPorts.Add_SelectionChanged({
    param($sender, $eventArgs)
    if ($gridPorts.SelectedRows.Count -le 0) {
        $txtPortDetails.Text = 'Select a port row to view details.'
        return
    }
    $row = $gridPorts.SelectedRows[0]
    $port = [string]$row.Cells['Port'].Value
    $service = [string]$row.Cells['Service'].Value
    $category = [string]$row.Cells['Category'].Value
    $listenerState = [string]$row.Cells['ListenerState'].Value
    $ruleState = [string]$row.Cells['RuleState'].Value
    $reason = ''
    if ($gridPorts.Columns.Contains('Reason') -and $null -ne $row.Cells['Reason'].Value) {
        $reason = [string]$row.Cells['Reason'].Value
    }
    $txtPortDetails.Text = "Selected Port:`r`n- Port: $port ($service)`r`n- Category: $category`r`n- Listener: $listenerState`r`n- Rule: $ruleState`r`n- Note: $reason"
})

$gridPorts.Add_MouseWheel({
    param($sender, $eventArgs)
    $step = [System.Windows.Forms.SystemInformation]::MouseWheelScrollLines
    if ($step -le 0) { $step = 3 }
    $deltaRows = if ($eventArgs.Delta -gt 0) { -1 * $step } elseif ($eventArgs.Delta -lt 0) { $step } else { 0 }
    if ($deltaRows -ne 0) {
        Scroll-PortGridBy -Grid $gridPorts -VBar $vScrollPorts -HBar $hScrollPorts -DeltaRows $deltaRows
    }
})

$gridPorts.Add_MouseEnter({
    param($sender, $eventArgs)
    $gridPorts.Focus() | Out-Null
})

$gridPorts.Add_MouseDown({
    param($sender, $eventArgs)
    $gridPorts.Focus() | Out-Null
})

$gridPorts.Add_KeyDown({
    param($sender, $eventArgs)
    if ($gridPorts.RowCount -le 0) { return }

    $currentIndex = 0
    if ($gridPorts.CurrentCell) {
        $currentIndex = [int]$gridPorts.CurrentCell.RowIndex
    } elseif ($gridPorts.SelectedRows.Count -gt 0) {
        $currentIndex = [int]$gridPorts.SelectedRows[0].Index
    }

    $visibleRows = [Math]::Max(1, $gridPorts.DisplayedRowCount($false))
    $target = $currentIndex

    switch ($eventArgs.KeyCode) {
        'Down'     { $target = $currentIndex + 1 }
        'Up'       { $target = $currentIndex - 1 }
        'PageDown' { $target = $currentIndex + $visibleRows }
        'PageUp'   { $target = $currentIndex - $visibleRows }
        'End'      { $target = $gridPorts.RowCount - 1 }
        'Home'     { $target = 0 }
        default    { return }
    }

    $target = [Math]::Max(0, [Math]::Min($gridPorts.RowCount - 1, $target))
    try {
        $gridPorts.CurrentCell = $gridPorts.Rows[$target].Cells[0]
        $gridPorts.Rows[$target].Selected = $true
    } catch {}

    $first = 0
    try { $first = $gridPorts.FirstDisplayedScrollingRowIndex } catch { $first = 0 }
    if ($first -lt 0) { $first = 0 }
    if ($target -lt $first) {
        try { $gridPorts.FirstDisplayedScrollingRowIndex = $target } catch {}
    } elseif ($target -ge ($first + $visibleRows)) {
        $newTop = [Math]::Max(0, $target - $visibleRows + 1)
        try { $gridPorts.FirstDisplayedScrollingRowIndex = $newTop } catch {}
    }

    Update-PortGridVirtualScrollBars -Grid $gridPorts -VBar $vScrollPorts -HBar $hScrollPorts
    $eventArgs.Handled = $true
    $eventArgs.SuppressKeyPress = $true
})


$trackZoom.Add_ValueChanged({
    param($sender, $eventArgs)
    $script:auditZoomPercent = $trackZoom.Value
    $lblZoomValue.Text = "$($trackZoom.Value)%"
    $script:auditScrollThickness = Get-ScrollThicknessFromZoom -Percent $script:auditZoomPercent
    Layout-AuditViewport -Tab $tabAudit -Grid $gridAudit -VBar $vScrollAudit -HBar $hScrollAudit -Thickness $script:auditScrollThickness
    Set-GridZoom -Grid $gridAudit -Percent $script:auditZoomPercent
    Update-AuditVirtualScrollBars -Grid $gridAudit -VBar $vScrollAudit -HBar $hScrollAudit
})

$trackRecoZoom.Add_ValueChanged({
    param($sender, $eventArgs)
    $script:recoZoomPercent = $trackRecoZoom.Value
    $lblRecoZoomValue.Text = "$($trackRecoZoom.Value)%"
    $script:recoScrollThickness = Get-ScrollThicknessFromZoom -Percent $script:recoZoomPercent
    Layout-AuditViewport -Tab $tabRecommendations -Grid $gridReco -VBar $vScrollReco -HBar $hScrollReco -Thickness $script:recoScrollThickness -TopScrollY $script:recoViewportTop
    Set-GridZoom -Grid $gridReco -Percent $script:recoZoomPercent
    Update-AuditVirtualScrollBars -Grid $gridReco -VBar $vScrollReco -HBar $hScrollReco
})

$getSelectedFixId = {
    $raw = [string]$cmbFixes.SelectedItem
    if (-not $raw) { return '' }
    return ($raw.Split('|')[0].Trim())
}

$btnPreviewFix.Add_Click({
    $fixId = & $getSelectedFixId
    $txtFixOutput.Text = Preview-HardeningFix -FixId $fixId
})

$btnApplyFix.Add_Click({
    $fixId = & $getSelectedFixId
    try {
        $msg = Apply-HardeningFix -FixId $fixId -RollbackState $script:rollbackJournal
        $txtFixOutput.Text = $msg
        $script:lastPortDetails = Get-ListeningTcpPortDetails
        $script:lastContext = Get-EnvironmentContextInfo
        if ($script:lastFindings) {
            $script:lastSummary = Get-SecurityPostureSummary -Findings $script:lastFindings -PortDetails $script:lastPortDetails -Context $script:lastContext
            $lblScoreTitle.Text = "Security Posture Score: $($script:lastSummary.Score) / 100"
            $lblRiskLevel.Text = "Risk Level: $($script:lastSummary.RiskLevel)"
        }
    } catch {
        $txtFixOutput.Text = "Apply failed: $($_.Exception.Message)"
    }
})

$btnRollbackFix.Add_Click({
    $fixId = & $getSelectedFixId
    try {
        $msg = Rollback-HardeningFix -FixId $fixId -RollbackState $script:rollbackJournal
        $txtFixOutput.Text = $msg
    } catch {
        $txtFixOutput.Text = "Rollback failed: $($_.Exception.Message)"
    }
})

$btnExportRecoCsv.Add_Click({
    if (-not $script:lastSummary -or -not $script:lastRecommendations -or $script:lastRecommendations.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Generate recommendations first so the CSV report has current data.', 'CSV Report') | Out-Null
        return
    }

    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Filter = 'CSV files (*.csv)|*.csv'
    $dialog.FileName = "security-posture-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    if ($dialog.ShowDialog() -ne 'OK') { return }

    try {
        $basePath = $dialog.FileName
        $dir = Split-Path $basePath -Parent
        $name = [System.IO.Path]::GetFileNameWithoutExtension($basePath)

        $summaryPath = Join-Path $dir ($name + '-summary.csv')
        $alertsPath = Join-Path $dir ($name + '-alerts.csv')
        $checkPath = Join-Path $dir ($name + '-checklist.csv')
        $recoPath = Join-Path $dir ($name + '-recommendations.csv')

        $summaryObj = [pscustomobject]@{
            GeneratedUtc = [string](Get-Date -Format 'u')
            Score = [int]$script:lastSummary.Score
            RiskLevel = [string]$script:lastSummary.RiskLevel
            TopDriver1 = [string]$script:lastSummary.TopDrivers[0]
            TopDriver2 = [string]$script:lastSummary.TopDrivers[1]
            TopDriver3 = [string]$script:lastSummary.TopDrivers[2]
            BaselineScore = [string]$(if ($script:baselineSummary) { $script:baselineSummary.Score } else { '' })
            BaselineRiskLevel = [string]$(if ($script:baselineSummary) { $script:baselineSummary.RiskLevel } else { '' })
        }
        @($summaryObj) | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8

        $alertsOut = if ($script:lastAlerts -and $script:lastAlerts.Count -gt 0) {
            @($script:lastAlerts)
        } else {
            @([pscustomobject]@{ Risk = 'Info'; Pattern = 'None'; Evidence = 'No correlated pattern'; Interpretation = 'No clustered attack behavior detected.' })
        }
        @($alertsOut) | Export-Csv -Path $alertsPath -NoTypeInformation -Encoding UTF8

        $checklist = Get-ComplianceChecklist -PortDetails $script:lastPortDetails -Context $script:lastContext
        @($checklist) | Export-Csv -Path $checkPath -NoTypeInformation -Encoding UTF8

        @($script:lastRecommendations) | Export-Csv -Path $recoPath -NoTypeInformation -Encoding UTF8

        [System.Windows.Forms.MessageBox]::Show("CSV report exported:`r`n$summaryPath`r`n$alertsPath`r`n$checkPath`r`n$recoPath", 'CSV Report') | Out-Null
    } catch {
        $lineInfo = ''
        if ($_.InvocationInfo -and $_.InvocationInfo.ScriptLineNumber) {
            $lineInfo = " (line $($_.InvocationInfo.ScriptLineNumber))"
        }
        [System.Windows.Forms.MessageBox]::Show("Failed to export CSV report$($lineInfo): $($_.Exception.Message)", 'CSV Report') | Out-Null
    }
})

$gridAudit.Add_Scroll({
    param($sender, $eventArgs)
    Update-AuditVirtualScrollBars -Grid $gridAudit -VBar $vScrollAudit -HBar $hScrollAudit
})

$gridReco.Add_Scroll({
    param($sender, $eventArgs)
    Update-AuditVirtualScrollBars -Grid $gridReco -VBar $vScrollReco -HBar $hScrollReco
})

$gridAudit.Add_DataBindingComplete({
    param($sender, $eventArgs)
    Set-GridZoom -Grid $gridAudit -Percent $script:auditZoomPercent
    Update-AuditVirtualScrollBars -Grid $gridAudit -VBar $vScrollAudit -HBar $hScrollAudit
})

$gridReco.Add_DataBindingComplete({
    param($sender, $eventArgs)
    Set-GridZoom -Grid $gridReco -Percent $script:recoZoomPercent
    Update-AuditVirtualScrollBars -Grid $gridReco -VBar $vScrollReco -HBar $hScrollReco
})

$tabAudit.Add_Resize({
    param($sender, $eventArgs)
    Layout-AuditViewport -Tab $tabAudit -Grid $gridAudit -VBar $vScrollAudit -HBar $hScrollAudit -Thickness $script:auditScrollThickness
    Update-AuditVirtualScrollBars -Grid $gridAudit -VBar $vScrollAudit -HBar $hScrollAudit
})

$tabRecommendations.Add_Resize({
    param($sender, $eventArgs)
    Layout-AuditViewport -Tab $tabRecommendations -Grid $gridReco -VBar $vScrollReco -HBar $hScrollReco -Thickness $script:recoScrollThickness -TopScrollY $script:recoViewportTop
    Update-AuditVirtualScrollBars -Grid $gridReco -VBar $vScrollReco -HBar $hScrollReco
})

$tabPorts.Add_Resize({
    param($sender, $eventArgs)
    Update-PortGridVirtualScrollBars -Grid $gridPorts -VBar $vScrollPorts -HBar $hScrollPorts
})

$form.Add_MouseWheel({
    param($sender, $eventArgs)
    if ($tabs.SelectedTab -ne $tabPorts) { return }
    $cursorOnScreen = [System.Windows.Forms.Cursor]::Position
    $cursorInGrid = $gridPorts.PointToClient($cursorOnScreen)
    $inside = ($cursorInGrid.X -ge 0 -and $cursorInGrid.Y -ge 0 -and $cursorInGrid.X -lt $gridPorts.Width -and $cursorInGrid.Y -lt $gridPorts.Height)
    if (-not $inside) { return }
    $step = [System.Windows.Forms.SystemInformation]::MouseWheelScrollLines
    if ($step -le 0) { $step = 3 }
    $deltaRows = if ($eventArgs.Delta -gt 0) { -1 * $step } elseif ($eventArgs.Delta -lt 0) { $step } else { 0 }
    if ($deltaRows -ne 0) {
        Scroll-PortGridBy -Grid $gridPorts -VBar $vScrollPorts -HBar $hScrollPorts -DeltaRows $deltaRows
    }
})

$btnScan.Add_Click({
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $script:lastFindings = Get-PowerShellRiskFindings
        if ($script:lastFindings.Count -eq 0) {
            $displayRows = @(
                [pscustomobject]@{
                    Severity = 'Info'
                    Pattern = 'NoThreatsFound'
                    Source = 'Local Scan'
                    Location = 'N/A'
                    Evidence = 'No risky patterns matched in available history/log sources.'
                    Why = 'Continue monitoring and rerun scans periodically.'
                }
            )
            Set-GridData -Grid $gridAudit -Rows $displayRows
            Update-AuditVirtualScrollBars -Grid $gridAudit -VBar $vScrollAudit -HBar $hScrollAudit
            $lblAuditStatus.Text = 'Status: scan completed, no risky matches found.'
            [System.Windows.Forms.MessageBox]::Show('Scan completed with no matches. This can happen if no risky patterns were found in available logs/history.', 'Audit Complete') | Out-Null
            return
        }
        Set-GridData -Grid $gridAudit -Rows $script:lastFindings
        Update-AuditVirtualScrollBars -Grid $gridAudit -VBar $vScrollAudit -HBar $hScrollAudit
        $lblAuditStatus.Text = "Status: scan completed with $($script:lastFindings.Count) finding(s)."
        if ($gridAudit.Rows.Count -gt 0) {
            $gridAudit.Rows[0].Selected = $true
        }
    } catch {
        $lblAuditStatus.Text = 'Status: scan failed.'
        $lineInfo = ''
        if ($_.InvocationInfo -and $_.InvocationInfo.ScriptLineNumber) {
            $lineInfo = " (line $($_.InvocationInfo.ScriptLineNumber))"
        }
        [System.Windows.Forms.MessageBox]::Show("Audit scan failed$($lineInfo): $($_.Exception.Message)", 'Audit Error') | Out-Null
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})

$btnExport.Add_Click({
    if (-not $script:lastFindings -or $script:lastFindings.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('No findings to export. Run a scan first.', 'Export') | Out-Null
        return
    }

    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Filter = 'CSV files (*.csv)|*.csv'
    $dialog.FileName = "powershell-risk-findings-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    if ($dialog.ShowDialog() -eq 'OK') {
        $script:lastFindings | Export-Csv -Path $dialog.FileName -NoTypeInformation -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show("Exported to $($dialog.FileName)", 'Export') | Out-Null
    }
})

$btnThreatAnalysis.Add_Click({
    if (-not $script:lastFindings -or $script:lastFindings.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Run an audit scan first to populate findings for threat analysis.', 'Threat Analysis') | Out-Null
        return
    }

    try {
        $threatFindings = @(
            @($script:lastFindings) | ForEach-Object {
                [pscustomobject]@{
                    Severity = [string]$_.Severity
                    Pattern = [string]$_.Pattern
                    Source = [string]$_.Source
                    Location = [string]$_.Location
                    Evidence = [string]$_.Evidence
                    Why = [string]$_.Why
                }
            }
        )
        Show-ThreatAnalysisDialog $threatFindings
    } catch {
        $lineInfo = ''
        if ($_.InvocationInfo -and $_.InvocationInfo.ScriptLineNumber) {
            $lineInfo = " (line $($_.InvocationInfo.ScriptLineNumber))"
        }
        $stack = ''
        if ($_.ScriptStackTrace) {
            $stack = "`r`n$($_.ScriptStackTrace)"
        }
        [System.Windows.Forms.MessageBox]::Show("Threat Analysis failed$($lineInfo): $($_.Exception.Message)$stack", 'Threat Analysis') | Out-Null
    }
})

$refreshPorts = {
    $ports = @(Get-ListeningTcpPorts)
    $catalog = @(Get-HighRiskExternalPortCatalog)
    $catalogMap = @{}
    foreach ($entry in $catalog) {
        $catalogMap[[int]$entry.Port] = $entry
    }
    $combinedPorts = @(
        @($ports + @($catalog | ForEach-Object { [int]$_.Port })) |
        Sort-Object -Unique
    )

    $script:lastPortDetails = Get-ListeningTcpPortDetails
    $script:lastContext = Get-EnvironmentContextInfo
    $script:lastPorts = $ports
    $portRows = New-Object System.Collections.Generic.List[object]
    foreach ($p in $combinedPorts) {
        $isListening = ($ports -contains $p)
        $isBlocked = Test-InboundBlockRuleExists -Port $p
        $meta = $catalogMap[$p]
        $svc = if ($meta) { [string]$meta.Service } else { 'Detected Service' }
        $risk = if ($meta) { 'HighRisk' } else { 'Observed' }
        $listen = if ($isListening) { 'Listening' } else { 'NotListening' }
        $blocked = if ($isBlocked) { 'Blocked' } else { 'Unblocked' }
        $reason = if ($meta) { [string]$meta.Reason } else { 'Observed from local listening port scan.' }
        $portRows.Add([pscustomobject]@{
            Port = [int]$p
            Service = [string]$svc
            Category = [string]$risk
            ListenerState = [string]$listen
            RuleState = [string]$blocked
            Reason = [string]$reason
        })
    }
    Set-GridData -Grid $gridPorts -Rows @($portRows.ToArray())
    if ($gridPorts.Columns.Contains('Port')) { $gridPorts.Columns['Port'].Width = 60 }
    if ($gridPorts.Columns.Contains('Service')) { $gridPorts.Columns['Service'].Width = 120 }
    if ($gridPorts.Columns.Contains('Category')) { $gridPorts.Columns['Category'].Width = 85 }
    if ($gridPorts.Columns.Contains('ListenerState')) { $gridPorts.Columns['ListenerState'].Width = 95 }
    if ($gridPorts.Columns.Contains('RuleState')) { $gridPorts.Columns['RuleState'].Width = 85 }
    if ($gridPorts.Columns.Contains('Reason')) { $gridPorts.Columns['Reason'].Visible = $false }
    if ($gridPorts.RowCount -gt 0 -and $gridPorts.ColumnCount -gt 0) {
        try {
            $gridPorts.CurrentCell = $gridPorts.Rows[0].Cells[0]
            $gridPorts.Rows[0].Selected = $true
        } catch {}
    }
    Update-PortGridVirtualScrollBars -Grid $gridPorts -VBar $vScrollPorts -HBar $hScrollPorts
    $blockedCount = (@($portRows | Where-Object { $_.RuleState -eq 'Blocked' })).Count
    $listeningCount = (@($portRows | Where-Object { $_.ListenerState -eq 'Listening' })).Count
    $txtPortSummary.Text = "Port Summary:`r`n- Listed: $($combinedPorts.Count)`r`n- Listening: $listeningCount`r`n- Blocked: $blockedCount`r`n- HighRisk Catalog: $($catalog.Count)"
    $txtPortDetails.Text = 'Select a port row to view details.'
    $txtOutput.AppendText("[$(Get-Date -Format 'u')] Loaded $($ports.Count) listening ports + $($catalog.Count) high-risk catalog ports (total listed: $($combinedPorts.Count)).`r`n")
}

$btnRefreshPorts.Add_Click($refreshPorts)

$btnBlockSelected.Add_Click({
    if ($gridPorts.SelectedRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Select at least one row to block.', 'Port Lockdown') | Out-Null
        return
    }

    foreach ($row in $gridPorts.SelectedRows) {
        $port = 0
        if ($null -ne $row.Cells['Port'].Value) {
            [void][int]::TryParse([string]$row.Cells['Port'].Value, [ref]$port)
        }
        if ($port -le 0) {
            $txtOutput.AppendText("[$(Get-Date -Format 'u')] Skipped invalid selected row.`r`n")
            continue
        }
        try {
            $msg = Add-InboundBlockRule -Port $port
            $txtOutput.AppendText("[$(Get-Date -Format 'u')] $msg`r`n")
        } catch {
            $txtOutput.AppendText("[$(Get-Date -Format 'u')] Failed to block $($port): $($_.Exception.Message)`r`n")
        }
    }
    & $refreshPorts
})

$btnUnblockSelected.Add_Click({
    if ($gridPorts.SelectedRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Select at least one row to unblock.', 'Port Lockdown') | Out-Null
        return
    }

    foreach ($row in $gridPorts.SelectedRows) {
        $port = 0
        if ($null -ne $row.Cells['Port'].Value) {
            [void][int]::TryParse([string]$row.Cells['Port'].Value, [ref]$port)
        }
        if ($port -le 0) {
            $txtOutput.AppendText("[$(Get-Date -Format 'u')] Skipped invalid selected row.`r`n")
            continue
        }
        try {
            $msg = Remove-InboundBlockRule -Port $port
            $txtOutput.AppendText("[$(Get-Date -Format 'u')] $msg`r`n")
        } catch {
            $txtOutput.AppendText("[$(Get-Date -Format 'u')] Failed to unblock $($port): $($_.Exception.Message)`r`n")
        }
    }
    & $refreshPorts
})

$btnBlockCustom.Add_Click({
    $parsedPort = 0
    if (-not [int]::TryParse($txtCustomPort.Text, [ref]$parsedPort)) {
        [System.Windows.Forms.MessageBox]::Show('Enter a valid numeric port.', 'Port Lockdown') | Out-Null
        return
    }

    if ($parsedPort -lt 1 -or $parsedPort -gt 65535) {
        [System.Windows.Forms.MessageBox]::Show('Port must be between 1 and 65535.', 'Port Lockdown') | Out-Null
        return
    }

    try {
        $msg = Add-InboundBlockRule -Port $parsedPort
        $txtOutput.AppendText("[$(Get-Date -Format 'u')] $msg`r`n")
    } catch {
        $txtOutput.AppendText("[$(Get-Date -Format 'u')] Failed to block $($parsedPort): $($_.Exception.Message)`r`n")
    }
    & $refreshPorts
})

$btnUnblockCustom.Add_Click({
    $parsedPort = 0
    if (-not [int]::TryParse($txtCustomPort.Text, [ref]$parsedPort)) {
        [System.Windows.Forms.MessageBox]::Show('Enter a valid numeric port.', 'Port Lockdown') | Out-Null
        return
    }

    if ($parsedPort -lt 1 -or $parsedPort -gt 65535) {
        [System.Windows.Forms.MessageBox]::Show('Port must be between 1 and 65535.', 'Port Lockdown') | Out-Null
        return
    }

    try {
        $msg = Remove-InboundBlockRule -Port $parsedPort
        $txtOutput.AppendText("[$(Get-Date -Format 'u')] $msg`r`n")
    } catch {
        $txtOutput.AppendText("[$(Get-Date -Format 'u')] Failed to unblock $($parsedPort): $($_.Exception.Message)`r`n")
    }
    & $refreshPorts
})

$btnGenerateReco.Add_Click({
    if (-not $script:lastPortDetails -or $script:lastPortDetails.Count -eq 0) {
        $script:lastPortDetails = Get-ListeningTcpPortDetails
    }
    if (-not $script:lastContext) {
        $script:lastContext = Get-EnvironmentContextInfo
    }
    $recommendations = Get-HardeningRecommendations -Findings $script:lastFindings -ListeningPorts $script:lastPorts -PortDetails $script:lastPortDetails -Context $script:lastContext
    $script:lastRecommendations = @($recommendations)
    Set-GridData -Grid $gridReco -Rows $recommendations
    Update-AuditVirtualScrollBars -Grid $gridReco -VBar $vScrollReco -HBar $hScrollReco

    $summary = Get-SecurityPostureSummary -Findings $script:lastFindings -PortDetails $script:lastPortDetails -Context $script:lastContext
    $script:lastSummary = $summary
    if (-not $script:baselineSummary) { $script:baselineSummary = $summary }
    $lblScoreTitle.Text = "Security Posture Score: $($summary.Score) / 100"
    $lblRiskLevel.Text = "Risk Level: $($summary.RiskLevel)"
    $txtTopDrivers.Text = "Top 3 Risk Drivers:`r`n- $($summary.TopDrivers[0])`r`n- $($summary.TopDrivers[1])`r`n- $($summary.TopDrivers[2])"

    $alerts = Get-BehaviorCorrelationAlerts -Findings $script:lastFindings -PortDetails $script:lastPortDetails
    $script:lastAlerts = @($alerts)
    if ($alerts.Count -eq 0) {
        $txtBehaviorAlerts.Text = 'Attack Pattern Detected: none with current evidence set.'
    } else {
        $txtBehaviorAlerts.Text = ($alerts | ForEach-Object { "$($_.Risk): $($_.Pattern) | $($_.Interpretation)" }) -join "`r`n"
    }

    [System.Windows.Forms.MessageBox]::Show("Generated $($recommendations.Count) recommendations.", 'Recommendations') | Out-Null
})

& $refreshPorts

[void]$form.ShowDialog()



