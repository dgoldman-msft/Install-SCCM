function Install-SCCM {
    <#
        .SYNOPSIS
            Automated install of SCCM

        .DESCRIPTION
            This is a script to kick off an automated installation of SCCM

        .PARAMETER DomainContoller
            Domain Controller where accounts will be created

        .PARAMETER Domain
            Your domain

        .PARAMETER SCCMServer
            Name of your SCCM server if not on the same machine

        .PARAMETER LoggingPath
            Path to PowerShell transcript logging
            
        .PARAMETER IsoLocation
            Location to ISO folder where images are contained
        
        .PARAMETER SkipSoftwareInstall
            Skips installing SQL Report Viewer, ADK for Windows 10 and SSMS

        .PARAMETER SkipWindowsFeatures
            Skips installing windows features

        .PARAMETER SkipFirewallSetup
            Skips configuring firewall ports

        .EXAMPLE
            PS C:\> Install-SCCM

        .NOTES
            Installation notes: https://systemcenterdudes.com/complete-sccm-installation-guide-and-configuration/
    #>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]
        $DomainContoller = "DC1",

        [string]
        $SCCMServer = "SCCM",

        [string]
        $LoggingPath = "C:\Logs\SCCMInstall.Log",

        [string]
        $IsoLocation = "c:\Software\ConfigMgr\",

        [switch]
        $SkipSoftwareInstall,

        [switch]
        $SkipWindowsFeatures,

        [switch]
        $SkipFirewallSetup
    )

    begin {
      
        Write-Host -ForegroundColor Green "SCCM install process - Started"

        if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Host -ForegroundColor Yellow "You need to run PowerShell as an Administrator"
            return
        }
    }

    process {
        $script:parameters = $PSBoundParameters
        $script:domain = $env:USERDOMAIN
        
        Write-Host -ForegroundColor Green "Logging started"
        Start-Transcript -Path $LoggingPath -Append -IncludeInvocationHeader
        $imagesFound = Get-ChildItem -Path $IsoLocation -Filter '*.iso'

        try {
            Write-Host -ForegroundColor Green "Attempting to mount Configuration Manager ISO"
            foreach ($image in $imagesFound) {
                if ($image.Name -like "*configuration_manager*") {
                    if ($PSCmdlet.ShouldProcess("Mounting Configuration Manager ISO")) {
                        $mounted = Mount-DiskImage -ImagePath  (Join-Path -Path $IsoLocation -ChildPath $image) -Access ReadOnly -StorageType ISO -PassThru -ErrorAction SilentlyContinue
                        $volume = Get-DiskImage $mounted.ImagePath | Get-Volume
                        $script:driveLetter = $volume.DriveLetter + ":"
                        Write-Host -ForegroundColor Green "ISO mounted as $($volume.Driveletter) drive"
                        break
                    }
                    else {
                        Write-Host -ForegroundColor Red "Failure: ISO image failed mount!"
                        return
                    }
                }
                else {
                    Write-Host -ForegroundColor Red "No Configuration Manager image found"
                    return
                }
            }
        }
        catch {
            Write-Host -ForegroundColor Red "Error $_"
            return
        }

        Write-Verbose "Checking for ActiveDirectory module"
        if (Get-Module -Name ActiveDirectory -ListAvailable) { Write-Verbose "ActiveDirectory module found!" }
        else { 
            Write-Verbose "Installing ActiveDirectory module"
            Add-WindowsFeature -Name "RSAT-AD-PowerShell" –IncludeAllSubFeature
            Import-Module -Name ActiveDirectory
        }

        Write-Host -ForegroundColor Green "Checking local account and groups"
        try {
            if (Get-ADGroupMember -Identity 'Schema Admins' | Where-Object Name -eq ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split '\\')[1]) {
                Write-Host -ForegroundColor Green "Your account was found in the Schema Admins group"
            }
            else {
                Write-Host -ForegroundColor Red "Your account is not a member of the Schema Admins group. Adding to group membership"
                if ($PSCmdlet.ShouldProcess("Add member to Schema Admins group")) {
                    Add-ADGroupMember -Identity 'Schema Admins' -Members ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split '\\')[1] -Verbose -PassThru -ErrorAction Stop 
                    Write-Host -ForegroundColor Green "Your account is now part of the Schema Admins group"
                }
                else {
                    Throw
                }
            }
        }
        catch {
            Write-Host -ForegroundColor Red "Error $_"
            return
        }

        Write-Host -ForegroundColor Green "Checking to see if the schema has been extended for SCCM"
        if (Test-SchemaExtension) {
            Write-Host -ForegroundColor Green "Extending has already been extended for SCCM"
        }
        else {
            Write-Host -ForegroundColor Green "Extending schema for SCCM"
            try {
                Set-Location -Path $script:driveLetter
                Start-Process -Filepath ".\SMSSETUP\BIN\X64\extadsch.exe" -Wait
                Set-Location -Path $env:SystemDrive

                if (Test-SchemaExtension) { 
                    Write-Host -ForegroundColor Green "SCCM Schmea extended!" 
                } 
                else {
                    Write-Host -ForegroundColor Red "SCCM has not been Schmea extended. Please check the SCCM logs for more information."
                    return
                } 
            }
            catch {
                Write-Host -ForegroundColor Red "Error $_"
                return
            }
        }

        Write-Host -ForegroundColor Green "Checking server versions"
        $serverVersion = Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption

        if (($serverVersion -match "Microsoft Windows Server 2012 R2") -or ($serverVersion -like "Microsoft Windows Server 2016*")`
                -or ($serverVersion -like "Microsoft Windows Server 2019*")) {
            Write-Host -ForegroundColor Green "OS version: $($serverVersion)"
        }
        else {
            Write-Host -ForegroundColor Red "Server version doesn't meet the requirements"
            return
        }

        try {
            Write-Host -ForegroundColor Green "Checking for SCCM System Management Container in the Active Directory"
            Get-ADObject -LDAPFilter "(objectClass=Container)" -SearchBase "CN=System Management,CN=System,DC=$script:domain,DC=com"
            Write-Host -ForegroundColor Green "SCCM System Management Container found!"
        }
        catch {
            try {
                if ($PSCmdlet.ShouldProcess("SCCM System Management Container")) {
                    New-ADObject -Name 'System Management' -Type 'Container' -Description 'SCCM System Management Container' -Path "CN=System,DC=$script:domain,DC=com" -Server $DomainContoller -PassThru -ErrorAction Stop 
                    Write-Host -ForegroundColor Green "SCCM System Management container created"
                }
            }
            catch {
                Write-Host -ForegroundColor Red "Failure: SCCM System Management container not created"
                return
            }
        }

        try {
            Write-Host -ForegroundColor Green "Setting SCCM System Management Container permissions"
            if ($PSCmdlet.ShouldProcess("Setting SCCM system mManagement container permissions")) {
                $acl = Get-Acl "AD:CN=System Management,CN=System,DC=$script:domain,DC=com" -ErrorAction Stop
                $computer = Get-ADComputer $SCCMServer -ErrorAction Stop
                $sid = [System.Security.Principal.SecurityIdentifier] $computer.SID
                $identity = [System.Security.Principal.IdentityReference] $SID
                $adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
                $type = [System.Security.AccessControl.AccessControlType] "Allow"
                $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity, $adRights, $type, $inheritanceType
                $acl.AddAccessRule($ace)
                if (Set-Acl -AclObject $acl "AD:CN=System Management,CN=System,DC=$script:domain,DC=com" -ErrorAction Stop -Passthru) {
                    Write-Host -ForegroundColor Green "SCCM System Management Container permissions set!"
                }
                else {
                    Write-Host -ForegroundColor Red "Failure: SCCM System Management Container permissions set!"
                    return
                }
            }
        }
        catch {
            Write-Host -ForegroundColor Red "Error $_"
            return
        }

        try {
            Write-Host -ForegroundColor Green "Creating SCCM accounts and groups"
            
            if ($PSCmdlet.ShouldProcess("Creating new managed SCCM-SQLService account")) {
                if (New-ADServiceAccount -Name 'SCCM-SQLService' -DNSHostName $DomainContoller -Enabled $True -PassThru) {
                    Write-Verbose "SCCM-SQLService created!" 
                }
            }
        }
        catch {
            if ($_.Exception.Message -eq "The specified account already exists") {
                Write-Host -ForegroundColor Yellow "SCCM-SQLService found!" 
                
            }
            elseif ($_.Exception.Message -eq "The specified account already exists") {
                Write-Host -ForegroundColor Red "KdsRootKey not found. Adding it" 
                try { 
                    Add-KdsRootKey -EffectiveTime ((get-date).addhours(-10)) -ErrorAction Stop 
                }
                catch { 
                    Write-Host -ForegroundColor Red "KdsRootKey not found. Adding it" 
                    return
                }
            }
        }

        try {
            if (-NOT ($parameters.ContainsKey("SkipFirewallSetup"))) {
                Write-Host -ForegroundColor Green "Setting necessary Firewall ports"
                if ($PSCmdlet.ShouldProcess("Setting Firewall Port Settings")) {
                    Write-Verbose "Enabling SQLServer default instance port 1433"
                    $null = netsh advfirewall firewall add rule name="SQL Server" dir=in action=allow protocol=TCP localport=1433
                    Write-Verbose "Dedicated Admin Connection port 1434"
                    $null = netsh advfirewall firewall add rule name="SQL Admin Connection" dir=in action=allow protocol=TCP localport=1434
                    Write-Verbose "conventional SQL Server Service Broker port 4022"
                    $null = netsh advfirewall firewall add rule name="SQL Service Broker" dir=in action=allow protocol=TCP localport=4022
                    Write-Verbose "Transact-SQL Debugger/RPC port 135"
                    $null = netsh advfirewall firewall add rule name="SQL Debugger/RPC" dir=in action=allow protocol=TCP localport=135
                    Write-Verbose "Enabling SSAS Default Instance port 2383"
                    $null = netsh advfirewall firewall add rule name="Analysis Services" dir=in action=allow protocol=TCP localport=2383
                    Write-Verbose "Enabling SQL Server Browser Service port 2382"
                    $null = netsh advfirewall firewall add rule name="SQL Browser" dir=in action=allow protocol=TCP localport=2382
                    Write-Verbose "Enabling HTTP port 80"
                    $null = netsh advfirewall firewall add rule name="HTTP" dir=in action=allow protocol=TCP localport=80
                    Write-Verbose "Enabling SSL port 443"
                    $null = netsh advfirewall firewall add rule name="SSL" dir=in action=allow protocol=TCP localport=443
                    Write-Verbose "Enabling port for SQL Server Browser Services Browse Button"
                    $null = netsh advfirewall firewall add rule name="SQL Browser" dir=in action=allow protocol=TCP localport=1434
                    Write-Verbose "Allowing Ping command"
                    $null = netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8, any dir=in action=allow
                }
            }
        }
        catch {
            Write-Host -ForegroundColor Red "Error $_"
            return
        }
    
        try {
            if (-NOT ($parameters.ContainsKey("SkipWindowsFeatures"))) {
                Write-Host -ForegroundColor Green "Installing Windows Features"
                $windowsFeatures = @('Web-Windows-Auth', 'Web-ISAPI-Ext' , 'Web-Metabase' , 'Web-WMI' , 'BITS', 'RDC', 'NET-Framework-Features', 'Web-Asp-Net', 'Web-Asp-Net45', 'NET-HTTP-Activation', 'NET-Non-HTTP-Activ')
                foreach ($feature in $windowsFeatures) { Install-WindowsFeature -Name $feature -ErrorAction Stop }
            }
        }
        catch {
            Write-Host -ForegroundColor Red "Error $_"
            return
        }
        
        try {
            if (-NOT ($parameters.ContainsKey("SkipSoftwareInstall"))) {
                Write-Host -ForegroundColor Green "Installing SQL Report Viewer, ADK for Windows 10 and SSMS"
                $urls = @(
                    @("SQLServerReportingServices.exe", "https://download.microsoft.com/download/1/a/a/1aaa9177-3578-4931-b8f3-373b24f63342/SQLServerReportingServices.exe", "/quiet /norestart /IAcceptLicenseTerms /Edition=Dev"),
                    @("adksetup.exe", "https://download.microsoft.com/download/9/A/E/9AE69DD5-BA93-44E0-864E-180F5E700AB4/adk/adksetup.exe?ocid=tia-235208000", "/quiet /installpath c:\ADK /features OptionId.DeploymentTools OptionId.WindowsPreinstallationEnvironment OptionId.UserStateMigrationTool"),
                    @("SSMS-Setup-ENU.exe", "https://download.microsoft.com/download/4/6/8/4681f3b2-f327-4d3d-8617-264b20685be0/SSMS-Setup-ENU.exe", "/install /quiet /norestart")
                )
                
                foreach ($url in $urls) {
                    $outpath = "$env:TEMP\$($url[0])"
                    if ($PSCmdlet.ShouldProcess("Installing Software")) {
                        Invoke-WebRequest -Uri $url[1] -OutFile $outpath 
                        Write-Host -ForegroundColor Green "Downloading and installing $($url[0])"
                        $cmdArguements = $url[2]
                        Start-Process -Filepath $outpath -ArgumentList $cmdArguements -Wait 
                    }
                }
                Write-Host -ForegroundColor Cyan "You can now kick off the SCCM installation!"
            }
        }
        catch {
            Write-Host -ForegroundColor Red "Error $_"
            return
        }

        Write-Host -ForegroundColor Green "Open 'https://systemcenterdudes.com/complete-sccm-installation-guide-and-configuration/' and skip down to 'NEW SCCM INSTALLATION'"
        Write-Verbose "Restoring ConfirmPreference"
        $ConfirmPreference = $OldConfirmPreference
        Write-Verbose "Dismounting the $($volume.DriveLetter) drive"
        Stop-Transcript
        Write-Host -ForegroundColor Green "Logging stopped. Logs can be found at: $LoggingPath"
    }

    end {
        Write-Host -ForegroundColor Green "SCCM install process - Finished!"
    }
}

function Test-SchemaExtension {
    <#
        .SYNOPSIS
            Test for schema extension

        .DESCRIPTION
            Test to see if the schema has already been extended for SCCM

        .EXAMPLE
            c:\ PS> Test-SchemaExtension

        .NOTES
            Internal method
    #>

    [cmdletbinding()]
    param()
    
    if (Test-path -Path "$env:SystemDrive\ExtADSch.log") {
        $content = Get-Content -Path "$env:SystemDrive\ExtADSch.log"
        foreach ($line in $content) { if ($line.contains("Successfully extended the Active Directory schema.")) { $true } }
    }
    else { $false }
}