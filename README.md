# Install-SCCM

Helper function to install everything for Sccm (minus SQL and SCCM)

## Getting Started

1. Run Set-ExecutionPolicy -ExecutionPolicy Bypass or Unrestricted
2. Install SQL Server Enterprise on the server
3. Download an ISO of Configuration Managmner
4. Click on the Install-SCCM.ps1
5. Click on 'Raw' and copy the script - Downloading from Github is corrupting the script on line 280
6. Save script locally as Install-Sccm.ps1
7. Dot source script into local PowerShell session: . .\Install-Sccm.ps1
8. Run Install-SCCM -DomainController DC1 -SCCMServer SCCM -IsoLocation 'c:\ISOs\'

## Notes

1. I purposely set $ConfirmationPreference to 'High' because we are making critical changes to the Active Directory structure (Containers, Managed Services, Accounts, etc.)
2. You need to run this script from the directory where the ISO for SCCM so we can extend the schema
3. This script supports ShouldProcess which means you can run the script with -Verbose -Whatif for an entire readonly trial run

## What will this script do?

1. Check to make sure your are running PowerShell as an Administrator
2. Start transcript logging
3. Check for the Configuration Manager ISO and mount it
4. Check for the ActiveDirectory module and if not found install the windows role and import it
5. Check to make sure account running is part of the Schema Admins group
6. Check the Windows version
7. Extend the schema for Configuration Manager
8. Check for the SCCM System Management Container in the Active Directory and if not found create the container
9. Add the SCCM computer to the container
10. Apply necessary permissions to the conatiner
11. Create an SCCM mannaged service account in the Active Directory
12. Set all necessary Firewall port rules
13. Install Windows Features needed for SCCM
14. Download and install SQL Report Viewer, ADK for Windows 10 and SSMS
