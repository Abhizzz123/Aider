# **Aider - Advanced Intrusion Detection and Enhanced Review Tool**

Aider is a comprehensive **security auditing tool** for Unix-based systems, designed to identify system misconfigurations and vulnerabilities. Through a series of checks on files, processes, permissions, and network configurations, Aider generates insightful reports and tracks system security improvements over time by comparing with historical data.

---

## **Features**

- **Vulnerability Detection**: Identifies critical, high, medium, and low vulnerabilities in system configurations.
- **Process Monitoring**: Monitors suspicious processes and high resource usage.
- **File Integrity Checks**: Examines critical files and permissions for anomalies.
- **Network Security Analysis**: Detects open ports and insecure firewall configurations.
- **Security Recommendations**: Provides actionable insights to strengthen system security.

---

## **Installation**

### **Dependencies**

Aider requires the following tools:
- `find`, `grep`, `awk`, `sed`
- `ss`, `systemctl` (or `launchtl` for macOS)
- `debsums` (for Debian systems)
- `bc` (for arithmetic operations)

### macOS dependencies

- `bc`
   ```console
  brew install bc
- `rkhunter`
  ```console
  brew install rkhunter
### **Installation Steps**

1. ***Download the specific version of Aider for your operating system:***
    - [Download for macOS](https://github.com/Abhizzz123/Aider/releases/download/v1.0.0/AiderMac.sh)
    - [Download for Linux](https://github.com/Abhizzz123/Aider/releases/download/v1.0.0/Aider-linux.sh)  

      **or**
      
    ***Clone the Repository***:
   ```console
   git clone https://github.com/Abhizzz123/aider.git
   cd aider
3. **Make the Script Executable:**
   ```console
   chmod +x Aider.sh
   ```


4. **Usage**
   ```console
    sudo ./Aider.sh
   ```
5. **Example**
   ```console
   [+] Checking dependencies...
   [✓] All dependencies satisfied

     █████╗ ██╗██████╗ ███████╗██████╗                                                                                                                                                
    ██╔══██╗██║██╔══██╗██╔════╝██╔══██╗                                                                                                                                               
    ███████║██║██║  ██║█████╗  ██████╔╝                                                                                                                                               
    ██╔══██║██║██║  ██║██╔══╝  ██╔══██╗                                                                                                                                               
    ██║  ██║██║██████╔╝███████╗██║  ██║                                                                                                                                               
    ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝                                                                                                                                               

   Advanced Intrusion Detection & Enhanced Review Tool
   Version 1.1 - Developed fby Triada


   Author       : Elishah                                                                                                                                                                
   Tool         : Aider - Advanced Intrusion Detection and Enhanced Review Tool                                                                                                          
   Usage        : sudo ./Aider.sh                                                                                                                                                   
   Description  : Aider performs a comprehensive security audit on Unix-based systems,                                                                                                   
                : focusing on system misconfigurations and vulnerabilities.                                                                                                             
                : It generates detailed reports and compares results with                                                                                                               
                : historical data to track security improvements over time.                                                                                                             

   ==============( System Information )=================

    * Hostname       : MacBook-Air                                                                                                                                                    
    * OS             : Kali GNU/Linux Rolling                                                                                                                                         
    * Kernel         : 6.10.9-arm64                                                                                                                                                   
    * Architecture   : aarch64                                                                                                                                                        
    * CPU            :                                                                                                                                                                
    * Date           : Tue Oct 29 01:53:59 EDT 2024                                                                                                                                   
                                                                                                                                                                                      

   ==============( Starting Security Audit )=================
   Initializing security checks...

   ╔══════════════════════════════════════════════════════╗
   ║             Basic Vulnerability Scan                 ║
   ╚══════════════════════════════════════════════════════╝

   [⠙] Checking system vulnerabilities
         [✓]SSH configuration check completed

   [⠹] Checking system vulnerabilities
         [✓] World-writable files check completed

   [✓] Shellshock vulnerability check completed

   
## **License**
This project is licensed under the MIT License.

## **Contributing**
Contributions are welcome! Please fork this repository, create a branch, and submit a pull request with a detailed explanation of your changes.
