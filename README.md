# Install-SCCM

Helper function to install everything for Sccm (minus SQL and SCCM)

## Getting Started

1. Install SQL Server Enterprise on the server
2. Download an ISO of Configuration Managmner
3. Download this script to the directory where both ISO's resides
4. Dot source script into local PowerShell session: . .\Install-Sccm.ps1
5. Run Install-SCCM -DomainController DC1 -SCCMServer SCCM

## Notes

1. I purposely set $ConfirmationPreference to 'High' because we are making critical changes to the Active Directory structure (Containers, Managed Services, Accounts, etc.)
2. You need to run this script from the directory where the ISO for SCCM so we can extend the schema
3. This script supports ShouldProcess which means you can run the script with -Verbose -Whatif for an entire readonly trial run

## What will this script do?

1. Check to make sure your are running PowerShell as an Administrator
2. Start transcript logging
3. Check for the ActiveDirectory module and if not found install the windows role and import it
4. Check to make sure account running is part of the Schema Admins group
5. Check the Windows version
6. Check for the SCCM System Management Container in the Active Directory and if not found create the container
7. Add the SCCM computer to the container
8. Apply necessary permissions to the conatiner
9. Create an SCCM mannaged service account in the Active Directory
10. Set all necessary Firewall port rules
11. Install Windows Features needed for SCCM
12. Download and install SQL Report Viewer, ADK for Windows 10 and SSMS
