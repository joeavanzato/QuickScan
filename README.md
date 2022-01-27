# QuickScan
 Hunting for Abnormalities

Uses some awesome existing repositories:
* https://github.com/chenerlich/FCL
* https://Neo23x0/signature-base
* https://github.com/yaml/pyyaml
* 

### Scheduled Tasks
* Abnormally Short-Named Binaries [DONE]
* Potentially Dangerous Extension [DONE]
* Binaries in User Locations
* Recently Added
* 

### Services
* Abnormally Short-Named Binaries [DONE]
* Starting from User Directory [DONE]
* 

### Registry
* RunOnce/RunServices/Run etc
* Extension Hijacking
* Debug
* ShimDB
* Program Associations

### Suspicious Files Names
* Checking certain paths for known-dangerous redteam/malware file names [DONE]
*

### Suspicious Extensions
* Checking certain paths for known-dangerous extensions [DONE]
*

### AmCache 

### False Extensions
* Recursively check certain paths for file names with a trailing space which may be an obfuscation technique [DONE]
* Check certain files and compare current extension with known magic byte identifier

### Prefetch
* Checking for known-dangerous redteam/malware names file Names [DONE]
* 

### Network Connections
* Checking Active TCP Connections for suspicious properties (SMB, RDP, TelNet, SSH, WinRM) [DONE]
* Checking qwinsta/quser for Active Connections
* 

### NTUSER.DAT Analysis

### Internet History
* Check for suspicious TLDs
* Check for recently downloaded suspicious file-types

### Yara Scan
* YARA Scan suspicious file extensions
* YARA Scan suspicious / active processes

### Known Malicious Hashes
* Scanning dangerous extension types across certain paths for known malicious hashes [PARTIAL]
  * Done using Loki Signature Base currently, updated at runtime.
* TODO: Find additional high-fidelity datasets for integration.

### Known Suspicious IP Addresses
* Check active network connections for known C2/Evil

### PowerShell History
* Checking for dangerous commands/modules in history files

### PowerShell Script Logging
* Checking for dangerous commands/modules in Event Logs

### Execution Logging
* Checking for dangerous command-line usage in Event Logs

### Security Event Log
* Checking for Users Added to the System
* Checking for localgroup Modifications, Administrator Adds, etc
* Checking for brute-force style activity
* Checking for historical network logons

### Active Processes
* YARA scan active processes with relevant rules
* Check command-line for potential evil
* Check process path and other statistics for known bad patterns

### CIM Providers
* Check existing CIM providers for any potential tampering





