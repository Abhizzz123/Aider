#!/bin/bash

# Aider - Advanced Intrusion Detection and Enhanced Review Tool
# Version: 1.1
#
# This script performs a comprehensive security audit on Unix-based systems,
# focusing on system misconfigurations and vulnerabilities. It generates
# detailed reports and compares results with historical data.
#
# Usage: ./aider-updated3.sh [options]
# Run with --help for more information on available options.

# Strict error handling
#set -o errexit  # Exit on error
set -o nounset  # Exit on unde
set -o pipefail # Exit on pipe failure
 
# Define the log file path
LOG_FILE="/var/log/aider.log"

# Global variable declarations at the top of the script
total_tasks=0    # Will be set in main()
current_task=0   # Progress tracker
start_time=0     # Start time for ETA calculation

# Initialize progress tracking variables
   # Total number of security checks (could be dynamic if needed)
   # Tracks current task progress
progress_width=50 # Width of the progress bar

# Create the log file if it doesn’t exist
sudo touch "$LOG_FILE"
# Trap errors and provide clean exit

trap 'error_handler $? $LINENO $BASH_LINENO "$BASH_COMMAND" $(printf "::%s" ${FUNCNAME[@]:-})' ERR
trap 'cleanup' EXIT
trap 'handle_interrupt' INT TERM



handle_interrupt() {
    echo -e "\n${COLORS[YELLOW]}${COLORS[BOLD]}[!] Script interrupted by user.${COLORS[NC]}"
    echo "DEBUG: Before Summary - STATS[TOTAL_VULNS]=${STATS[TOTAL_VULNS]}"
    echo "DEBUG: Before Summary - STATS[CRITICAL_VULNS]=${STATS[CRITICAL_VULNS]}"
    echo "DEBUG: Before Summary - STATS[HIGH_VULNS]=${STATS[HIGH_VULNS]}"
    echo "DEBUG: Before Summary - STATS[MEDIUM_VULNS]=${STATS[MEDIUM_VULNS]}"
    echo "DEBUG: Before Summary - STATS[LOW_VULNS]=${STATS[LOW_VULNS]}"
    echo "DEBUG: Before Summary - STATS[CHECKS_COMPLETED]=${STATS[CHECKS_COMPLETED]}"
    echo "DEBUG: Before Summary - STATS[CHECKS_FAILED]=${STATS[CHECKS_FAILED]}"
    echo "DEBUG: Before Summary - STATS[TOTAL_VULNS]=${STATS[TOTAL_VULNS]}"
    echo "DEBUG: Before Summary - STATS[CRITICAL_VULNS]=${STATS[CRITICAL_VULNS]}"
    echo "DEBUG: Before Summary - STATS[HIGH_VULNS]=${STATS[HIGH_VULNS]}"
    echo "DEBUG: Before Summary - STATS[MEDIUM_VULNS]=${STATS[MEDIUM_VULNS]}"
    echo "DEBUG: Before Summary - STATS[LOW_VULNS]=${STATS[LOW_VULNS]}"
    echo "DEBUG: Before Summary - STATS[CHECKS_COMPLETED]=${STATS[CHECKS_COMPLETED]}"
    echo "DEBUG: Before Summary - STATS[CHECKS_FAILED]=${STATS[CHECKS_FAILED]}"
    display_vulnerability_summary
    generate_partial_report
    echo -e "\n${COLORS[RED]}${COLORS[BOLD]}[!] AIDER Exited Succesfully...${COLORS[NC]}"
    exit 1
}

cleanup() {
    # Save cursor position
    tput sc
    
    # Kill background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    
    # Generate reports if needed
    if [ ${STATS[TOTAL_VULNS]} -gt 0 ]; then
        echo "DEBUG: Before Summary - STATS[TOTAL_VULNS]=${STATS[TOTAL_VULNS]}"
        echo "DEBUG: Before Summary - STATS[CRITICAL_VULNS]=${STATS[CRITICAL_VULNS]}"
        echo "DEBUG: Before Summary - STATS[HIGH_VULNS]=${STATS[HIGH_VULNS]}"
        echo "DEBUG: Before Summary - STATS[MEDIUM_VULNS]=${STATS[MEDIUM_VULNS]}"
        echo "DEBUG: Before Summary - STATS[LOW_VULNS]=${STATS[LOW_VULNS]}"
        echo "DEBUG: Before Summary - STATS[CHECKS_COMPLETED]=${STATS[CHECKS_COMPLETED]}"
        echo "DEBUG: Before Summary - STATS[CHECKS_FAILED]=${STATS[CHECKS_FAILED]}"
        display_vulnerability_summary
    fi
    
    # Save logs
    if [ -f "$LOG_FILE" ]; then
        cp "$LOG_FILE" "${CONFIG[REPORT_DIR]}/audit.log" 2>/dev/null || true
    fi
    
    # Generate partial report if needed
    if [ ${STATS[CHECKS_COMPLETED]} -gt 0 ]; then
        generate_partial_report
    fi
    
    # Remove temporary files
    rm -f /tmp/aider_tmp_* 2>/dev/null || true
    
    # Restore cursor position and show it
    tput rc
    tput cnorm
    
    echo -e "\n${COLORS[BOLD]}${COLORS[BLUE]}[*] Cleanup completed${COLORS[NC]}"
}

# Global variables with defaults
declare -A CONFIG
CONFIG=(
    [REPORT_DIR]="/tmp/aider_test_results"
    [HTML_REPORT]=""
    [JSON_REPORT]=""
    [MARKDOWN_REPORT]=""
    [HISTORICAL_DIR]="$HOME/.security_audits"
    [LOG_FILE]="/var/log/aider.log"
    [Add.info]=false
    
)

declare -A SUSPICIOUS_SHELLS=(
    ["/bin/bash"]=0
    ["/bin/sh"]=0
    ["/bin/rbash"]=0
    ["/bin/dash"]=0
)

declare -A RISKY_DIRS=(
    ["/"]="root directory"
    ["/tmp"]="temporary directory"
    ["/var/tmp"]="temporary directory"
    ["/dev"]="device directory"
    ["/etc"]="system configuration directory"
)

declare -A COLORS=(
    [RED]='\033[0;31m'
    [RED_BOLD]='\033[1;31m'
    [GREEN]='\033[0;32m'
    [GREEN_BOLD]='\033[1;32m'
    [YELLOW]='\033[0;33m'
    [YELLOW_BOLD]='\033[1;33m'
    [BLUE]='\033[0;34m'
    [BLUE_BOLD]='\033[1;34m'
    [MAGENTA]='\033[0;35m'
    [MAGENTA_BOLD]='\033[1;35m'
    [CYAN]='\033[0;36m'
    [CYAN_BOLD]='\033[1;36m'
    [GREY]='\033[0;37m'
    [GREY_BOLD]='\033[1;37m'
    [BOLD]='\033[1m'
    [NC]='\033[0m'
    [LINE]='\033[2m'
)

declare -A DANGER=(
    [CRITICAL]="${COLORS[RED_BOLD]}[CRITICAL]${COLORS[NC]}"
    [HIGH]="${COLORS[RED]}[HIGH]${COLORS[NC]}"
    [MEDIUM]="${COLORS[YELLOW]}[MEDIUM]${COLORS[NC]}"
    [LOW]="${COLORS[GREEN]}[LOW]${COLORS[NC]}"
    [INFO]="${COLORS[BLUE]}[INFO]${COLORS[NC]}"
)

# Statistics tracking
declare -A STATS
STATS=(
        [TOTAL_VULNS]=0
        [CRITICAL_VULNS]=0
        [HIGH_VULNS]=0
        [MEDIUM_VULNS]=0
        [LOW_VULNS]=0
        [CHECKS_COMPLETED]=0
        [CHECKS_FAILED]=0
 )

declare -A SYMBOLS=(
    ["CRITICAL"]="✘"  # Cross mark for critical
    ["HIGH"]="!"      # Exclamation for high
    ["MEDIUM"]="●"    # Dot for medium
    ["LOW"]="•"       # Small dot for low
    ["INFO"]="ℹ"      # Info symbol
)
# Colors and formatting

# Animation frames for different spinners
declare -A SPINNERS
SPINNERS=(
    [DEFAULT]='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    [DOTS]='⠁⠂⠄⡀⢀⠠⠐⠈'
    [ARROWS]='←↖↑↗→↘↓↙'
)

# Error handling function
error_handler() {
    local exit_code=$1
    local line_no=$2
    local bash_lineno=$3
    local last_command=$4
    local func_trace=$5

    # Log the error
    log_error "Error $exit_code occurred at line $line_no"
    log_error "Command: $last_command"
    log_error "Function trace: $func_trace"

    # User-friendly error message
    echo -e "\n${COLORS[RED]}${COLORS[BOLD]}[!] An error occurred while running the security audit${COLORS[NC]}"
    echo -e "${COLORS[BOLD]}Don't worry - partial results have been saved${COLORS[NC]}"

    # Attempt to save partial results
    generate_partial_report

    # Cleanup and exit gracefully
    cleanup
    exit 1
}

# Logging functions
log_error() {
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1" >> "${CONFIG[LOG_FILE]}"
    if ${CONFIG[Add.info]}; then
        echo -e "${COLORS[RED]}${COLORS[BOLD]}[[Add.info]] $1${COLORS[NC]}" >&2
    fi
}

log_info() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1" >> "${CONFIG[LOG_FILE]}"
    if ${CONFIG[Add.info]}; then
        echo -e "${COLORS[BLUE]}${COLORS[BOLD]}[Add.info] $1${COLORS[NC]}"
    fi
}



# Function to print visually appealing section headers
print_section_header() {
    local title="$1"
    local width=50
    local padding=$(( (width - ${#title}) / 2 ))
    echo
    echo -e "${COLORS[CYAN]}${COLORS[BOLD]}╔══════════════════════════════════════════════════════╗${COLORS[NC]}"
    printf "${COLORS[CYAN]}${COLORS[BOLD]}║%*s%s%*s║${COLORS[NC]}\n" $padding "" "$title" $padding ""
    echo -e "${COLORS[CYAN]}${COLORS[BOLD]}╚══════════════════════════════════════════════════════╝${COLORS[NC]}"
    echo
}


display_vulnerability() {
    local level=$1
    local message=$2
    local details=$3
    
    # Select color and symbol based on level
    local color="${COLORS[BLUE]}"  # Default color
    local symbol="${SYMBOLS[INFO]}" # Default symbol
    
    case $level in
        "CRITICAL")
            color="${COLORS[RED]}"
            symbol="${SYMBOLS[CRITICAL]}"
            ;;
        "HIGH")
            color="${COLORS[RED]}"
            symbol="${SYMBOLS[HIGH]}"
            ;;
        "MEDIUM")
            color="${COLORS[YELLOW]}"
            symbol="${SYMBOLS[MEDIUM]}"
            ;;
        "LOW")
            color="${COLORS[GREEN]}"
            symbol="${SYMBOLS[LOW]}"
            ;;
        *)
            color="${COLORS[BLUE]}"
            symbol="${SYMBOLS[INFO]}"
            ;;
    esac
    
    # Display the main vulnerability message
    printf "${color}${symbol} %-8s${COLORS[NC]} %s\n" "[$level]" "$message"
    
    # Display details if provided
    if [ -n "$details" ]; then
        printf "${COLORS[GREY]}   └─>> %s${COLORS[NC]}\n" "$details"
    fi
}

# Function to display a colorful summary of vulnerabilities
display_vulnerability_summary() {
    local summary_file="${CONFIG[REPORT_DIR]}/vulnerability_summary.txt"
    print_section_header "Vulnerability Summary"

    local total=${STATS[TOTAL_VULNS]:-0}
    local critical=${STATS[CRITICAL_VULNS]:-0}
    local high=${STATS[HIGH_VULNS]:-0}
    local medium=${STATS[MEDIUM_VULNS]:-0}
    local low=${STATS[LOW_VULNS]:-0}
    local completed=${STATS[CHECKS_COMPLETED]:-0}
    local failed=${STATS[CHECKS_FAILED]:-0}


    echo "DEBUG: STATS[TOTAL_VULNS]=$total"
    echo "DEBUG: STATS[CRITICAL_VULNS]=$critical"
    echo "DEBUG: STATS[HIGH_VULNS]=$high"
    echo "DEBUG: STATS[MEDIUM_VULNS]=$medium"
    echo "DEBUG: STATS[LOW_VULNS]=$low"
    echo "DEBUG: STATS[CHECKS_COMPLETED]=$completed"
    echo "DEBUG: STATS[CHECKS_FAILED]=$failed"

    echo -e "${COLORS[BOLD]}Total Vulnerabilities: ${COLORS[RED]}${total}${COLORS[NC]}"
    echo -e "${COLORS[BOLD]}Critical Severity:     ${COLORS[RED]}${critical}${COLORS[NC]}"
    echo -e "${COLORS[BOLD]}High Severity:         ${COLORS[RED]}${high}${COLORS[NC]}"
    echo -e "${COLORS[BOLD]}Medium Severity:       ${COLORS[YELLOW]}${medium}${COLORS[NC]}"
    echo -e "${COLORS[BOLD]}Low Severity:          ${COLORS[GREEN]}${low}${COLORS[NC]}"
    echo
    echo -e "${COLORS[BOLD]}Checks Completed:      ${COLORS[BLUE]}${completed}${COLORS[NC]}"
    echo -e "${COLORS[BOLD]}Checks Failed:         ${COLORS[MAGENTA]}${failed}${COLORS[NC]}"
    echo

    local risk_level="LOW"
    if [ ${high} -gt 0 ]; then
        risk_level="HIGH"
    elif [ ${medium} -gt 0 ]; then
        risk_level="MEDIUM"
    fi

    echo -e "
${COLORS[BOLD]}Overall Risk Assessment: ${DANGER[$risk_level]}${COLORS[NC]}"

    echo "DEBUG: Writing summary to file: ${summary_file}"
    {
        echo "# Security Audit Summary"
        echo "Date: $(date)"
        echo "Total Vulnerabilities: $total"
        echo "Critical Vulnerabilities: $critical"
        echo "High Severity: $high"
        echo "Medium Severity: $medium"
        echo "Low Severity: $low"
        echo "Risk Level: $risk_level"
    } > "${summary_file}"
    echo "DEBUG: Summary written to file"
    echo -e "${COLORS[BOLD]}High Severity:         ${COLORS[RED]}${STATS[HIGH_VULNS]}${COLORS[NC]}"
    echo -e "${COLORS[BOLD]}Medium Severity:       ${COLORS[YELLOW]}${STATS[MEDIUM_VULNS]}${COLORS[NC]}"
    echo -e "${COLORS[BOLD]}Low Severity:          ${COLORS[GREEN]}${STATS[LOW_VULNS]}${COLORS[NC]}"
    echo
    echo -e "${COLORS[BOLD]}Checks Completed:      ${COLORS[BLUE]}${STATS[CHECKS_COMPLETED]}${COLORS[NC]}"
    echo -e "${COLORS[BOLD]}Checks Failed:         ${COLORS[MAGENTA]}${STATS[CHECKS_FAILED]}${COLORS[NC]}"
    echo

    local risk_level="LOW"
    if [ ${STATS[HIGH_VULNS]} -gt 0 ]; then
        risk_level="HIGH"
    elif [ ${STATS[MEDIUM_VULNS]} -gt 0 ]; then
        risk_level="MEDIUM"
    fi
    
    echo -e "\n${COLORS[BOLD]}Overall Risk Assessment: ${DANGER[$risk_level]}${COLORS[NC]}"

    {
        echo "# Security Audit Summary"
        echo "Date: $(date)"
        echo "Total Vulnerabilities: $total"
        echo "Critical Vulnerabilites: $critical"
        echo "High Severity: $high"
        echo "Medium Severity: $medium"
        echo "Low Severity: $low"
        echo "Risk Level: $risk_level"
    } > "${CONFIG[REPORT_DIR]}/summary.txt"
}
total_checks=0
completed_checks=0

# Function to display progress bar
# Function to run security checks with progress visualization
# Function to generate a detailed report
generate_detailed_report() {
    local report_file="${CONFIG[REPORT_DIR]}/detailed_report.md"

    echo "# Security Audit Detailed Report" > "$report_file"
    echo "## Summary" >> "$report_file"
    echo "- Total Vulnerabilities: ${STATS[TOTAL_VULNS]}" >> "$report_file"
    echo "- High Severity: ${STATS[HIGH_VULNS]}" >> "$report_file"
    echo "- Medium Severity: ${STATS[MEDIUM_VULNS]}" >> "$report_file"
    echo "- Low Severity: ${STATS[LOW_VULNS]}" >> "$report_file"
    echo "- Checks Completed: ${STATS[CHECKS_COMPLETED]}" >> "$report_file"
    echo "- Checks Failed: ${STATS[CHECKS_FAILED]}" >> "$report_file"

    echo "## Detailed Findings" >> "$report_file"
    # Add detailed findings from each check here

    echo -e "${COLORS[GREEN]}${COLORS[BOLD]}[✓] Detailed report generated: $report_file${COLORS[NC]}"
}

check_suid_sgid() {
    echo -e "\n${COLORS[BOLD]}[${COLORS[BLUE]}[*] Initiating SUID/SGID binary scan...${COLORS[NC]}\n"
    
    # Initialize counters
    local total_files=0
    local current=0
    local dangerous_count=0
    local regular_count=0
    declare -A dangerous_bins
    declare -A regular_bins
    
    echo -e "${COLORS[CYAN]}[⠙] Counting SUID/SGID binaries...${COLORS[NC]}"
    total_files=$(find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)
    
    if [ "$total_files" -eq 0 ]; then
        echo -e "\n${COLORS[GREEN]}[✓] No SUID/SGID binaries found${COLORS[NC]}"
        display_vulnerability "INFO" "No SUID/SGID binaries found" ""
        return 0
    fi
    
    echo -e "${COLORS[CYAN]}[*] Found ${COLORS[BOLD]}$total_files${COLORS[NC]}${COLORS[CYAN]} SUID/SGID binaries${COLROS[NC]}\n"
    echo -e "${COLORS[BOLD]}Scanning Details:${COLORS[NC]}"
    echo "═══════════════════"
    
    find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while IFS= read -r file; do
        ((current++))
        
        if [ -f "$file" ]; then
            perms=$(stat -c '%A' "$file" 2>/dev/null) || continue
            owner=$(stat -c '%U' "$file" 2>/dev/null) || continue
            group=$(stat -c '%G' "$file" 2>/dev/null) || continue
            last_mod=$(stat -c '%y' "$file" 2>/dev/null | cut -d. -f1) || continue
            
            # Determine if it's a dangerous binary
            case "$file" in
                *nmap*|*perl*|*python*|*ruby*|*lua*|*php*)
                    dangerous_bins["$file"]="$perms|$owner|$group|$last_mod"
                    display_vulnerability "CRITICAL" "Dangerous SUID Binary" "$file ($perms, owner: $owner)"
                    ((dangerous_count++))
                    ((STATS[HIGH_VULNS]++))
                    ;;
                *)
                    regular_bins["$file"]="$perms|$owner|$group|$last_mod"
                    display_vulnerability "MEDIUM" "SUID Binary" "$file ($perms, owner: $owner)"
                    ((regular_count++))
                    ((STATS[MEDIUM_VULNS]++))
                    ;;
            esac
            ((STATS[TOTAL_VULNS]++))
            
            # Show progress
            printf "\r${COLORS[CYAN]}[⠙] Progress: ${BOLD}%d/%d${COLORS[NC]} binaries scanned" "$current" "$total_files"
        fi
    done
    
    # Print Summary
    print_section_header "SUID/GUID Summary"
    echo -e "${COLORS[BOLD]}Total SUID/SGID binaries found:${COLORS[NC]} $total_files"
    echo -e "${COLORS[RED]}${COLORS[BOLD]}Dangerous binaries found:${COLORS[NC]} $dangerous_count"
    echo -e "${COLORS[YELLOW]}${COLORS[BOLD]}Regular SUID/SGID binaries:${COLORS[NC]} $regular_count"
    
    # Detailed Findings
    if [ $dangerous_count -gt 0 ]; then
        echo -e "\n${COLORS[RED]}${COLORS[BOLD]}Critical Findings - Dangerous SUID Binaries:${COLORS[NC]}"
        echo "══════════════════════════════════════════"
        for file in "${!dangerous_bins[@]}"; do
            IFS='|' read -r perms owner group last_mod <<< "${dangerous_bins[$file]}"
            echo -e "${COLORS[RED]}[!]${COLORS[NC]} ${COLORS[BOLD]}Binary:${COLORS[NC]} $file"
            echo "    ${COLORS[BOLD]}Permissions:${COLORS[NC]} $perms"
            echo "    ${COLORS[BOLD]}Owner/Group:${COLORS[NC]} $owner:$group"
            echo "    ${COLORS[BOLD]}Last Modified:${COLORS[NC]} $last_mod"
            echo
        done
    fi
    
    if [ $regular_count -gt 0 ]; then
        echo -e "\n${COLORS[YELLOW]}${COLORS[BOLD]}Regular SUID/SGID Binaries:${COLORS[NC]}"
        echo "═════════════════════════"
        for file in "${!regular_bins[@]}"; do
            IFS='|' read -r perms owner group last_mod <<< "${regular_bins[$file]}"
            echo -e "${COLORS[YELLOW]}[i]${COLORS[NC]} ${COLORS[BOLD]}Binary:${COLORS[NC]} $file"
            echo "    ${COLORS[BOLD]}Permissions:${COLORS[NC]} $perms"
            echo "    ${COLORS[BOLD]}Owner/Group:${COLORS[NC]} $owner:$group"
            echo "    ${COLORS[BOLD]}Last Modified:${COLORS[NC]} $last_mod"
            echo
        done
    fi
    
    # Recommendations
    echo -e "\n${COLORS[BOLD]}Security Recommendations:${COLORS[NC]}"
    echo "════════════════════════"
    echo -e "1. ${COLORS[BOLD]}Review all SUID/SGID binaries:${COLORS[NC]}"
    echo "   - Verify each binary is required for system operation"
    echo "   - Remove SUID/SGID bit from unnecessary binaries"
    
    if [ $dangerous_count -gt 0 ]; then
        echo -e "\n2. ${COLORS[BOLD]}${COLORS[RED]}Immediate Action Required:${COLORS[NC]}"
        echo "   - Remove SUID bit from dangerous binaries (nmap, perl, python, etc.)"
        echo "   - These binaries can be exploited for privilege escalation"
    fi
    
    echo -e "\n3. ${COLORS[BOLD]}Best Practices:${COLORS[NC]}"
    echo "   - Regularly audit SUID/SGID binaries"
    echo "   - Implement file integrity monitoring"
    echo "   - Consider using capabilities instead of SUID where possible"
    
    echo
}

quick_system_enum() {
    echo -e "\n${COLORS[BLUE]}${COLORS[BOLD]}=== Quick System Enumeration Check ===${COLORS[NC]}\n"
    local findings=()
    
    # Check kernel version and known vulnerabilities
    echo -e "${COLORS[CYAN]}[*] Kernel Information:${COLORS[NC]}"
    local kernel_version=$(uname -r)
    echo -e "    ├── Kernel Version: $kernel_version"
    
    # Check for common kernel exploits based on version
    if [[ "$kernel_version" =~ ^2\.6\. || "$kernel_version" =~ ^3\. ]]; then
        display_vulnerability "HIGH" "Outdated Kernel" "Kernel version $kernel_version might be vulnerable to known exploits"
        ((STATS[HIGH_VULNS]++))
        findings+=("Outdated kernel version: $kernel_version")
    fi

    # System Information
    echo -e "\n${COLORS[CYAN]}[*] System Information:${COLORS[NC]}"
    echo -e "    ├── Distribution: $(cat /etc/issue 2>/dev/null | head -n1)"
    echo -e "    ├── Architecture: $(uname -m)"
    echo -e "    └── Hostname: $(hostname)"

    # Check sudo configuration
    echo -e "\n${COLORS[CYAN]}[*] Sudo Configuration:${COLORS[NC]}"
    if command -v sudo >/dev/null 2>&1; then
        # Check sudo version for CVE-2021-3156
        local sudo_version=$(sudo -V | head -n1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
        echo -e "    ├── Sudo Version: $sudo_version"
        
        # Check for NOPASSWD entries
        if sudo -l 2>/dev/null | grep -q NOPASSWD; then
            display_vulnerability "HIGH" "Sudo NOPASSWD" "NOPASSWD directive found in sudo configuration"
            echo -e "    │   └── $(sudo -l 2>/dev/null | grep NOPASSWD)"
            ((STATS[HIGH_VULNS]++))
            findings+=("NOPASSWD sudo entries found")
        fi
        
        # Check for specific sudo rules that could be exploited
        if sudo -l 2>/dev/null | grep -qE "vi|vim|nano|less|more|man|tcpdump|docker|python|perl|ruby|gcc|nc|netcat|bash|sh|ksh|csh|awk|sed"; then
            display_vulnerability "HIGH" "Dangerous Sudo Rules" "Potentially exploitable sudo rules found"
            echo -e "    └── $(sudo -l 2>/dev/null | grep -E 'vi|vim|nano|less|more|man|tcpdump|docker|python|perl|ruby|gcc|nc|netcat|bash|sh|ksh|csh|awk|sed')"
            ((STATS[HIGH_VULNS]++))
            findings+=("Dangerous sudo rules detected")
        fi
    fi

    # Check for weak file permissions in sensitive paths
    echo -e "\n${COLORS[CYAN]}[*] Sensitive File Permissions:${COLORS[NC]}"
    local sensitive_paths=(
        "/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/crontab"
        "/etc/ssh/sshd_config" "/etc/hosts" "/etc/fstab"
        "/var/log/auth.log" "/var/log/syslog" "/var/log/wtmp"
        "/root/.bash_history" "/root/.ssh/id_rsa" "/root/.ssh/authorized_keys"
        "/var/www/html/wp-config.php" "/var/www/html/config.php"
    )

    for path in "${sensitive_paths[@]}"; do
        if [ -f "$path" ]; then
            local perms=$(stat -c "%a %U %G" "$path" 2>/dev/null)
            echo -e "    ├── $path: $perms"
            if [ -w "$path" ] && [ "$(id -u)" -ne 0 ]; then
                display_vulnerability "CRITICAL" "Writable Sensitive File" "$path is writable by current user"
                ((STATS[HIGH_VULNS]++))
                findings+=("Writable sensitive file: $path")
            fi
        fi
    done

    # Check for world-writable directories in $PATH
    echo -e "\n${COLORS[CYAN]}[*] PATH Security:${COLORS[NC]}"
    IFS=':' read -ra path_dirs <<< "$PATH"
    for dir in "${path_dirs[@]}"; do
        if [ -d "$dir" ] && [ -w "$dir" ] && [ "$(id -u)" -ne 0 ]; then
            display_vulnerability "HIGH" "Writable PATH Directory" "$dir is writable"
            ((STATS[HIGH_VULNS]++))
            findings+=("Writable PATH directory: $dir")
        fi
    done

    # Check for docker group membership
    echo -e "\n${COLORS[CYAN]}[*] Docker Privileges:${COLORS[NC]}"
    if groups 2>/dev/null | grep -q docker; then
        display_vulnerability "HIGH" "Docker Group Member" "Current user is member of docker group (possible privilege escalation)"
        ((STATS[HIGH_VULNS]++))
        findings+=("User in docker group")
    fi

    # Check for capabilities
    echo -e "\n${COLORS[CYAN]}[*] Capability Check:${COLORS[NC]}"
    if command -v getcap >/dev/null 2>&1; then
        local cap_files=$(getcap -r / 2>/dev/null)
        if [ ! -z "$cap_files" ]; then
            echo -e "    └── Files with capabilities:"
            while IFS= read -r line; do
                echo -e "        ├── $line"
                if echo "$line" | grep -qE "cap_setuid|cap_setgid|cap_sys_admin"; then
                    display_vulnerability "HIGH" "Dangerous Capability" "$line"
                    ((STATS[HIGH_VULNS]++))
                    findings+=("Dangerous capability: $line")
                fi
            done <<< "$cap_files"
        fi
    fi

    # Environment Variable Check
    echo -e "\n${COLORS[CYAN]}[*] Environment Variables:${COLORS[NC]}"
    if [ -z "$LD_LIBRARY_PATH" ]; then
        echo -e "    ├── LD_LIBRARY_PATH is not set"
    else
        echo -e "    ├── LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
        if [ -w "$LD_LIBRARY_PATH" ]; then
            display_vulnerability "HIGH" "Writable LD_LIBRARY_PATH" "LD_LIBRARY_PATH contains writable directory"
            ((STATS[HIGH_VULNS]++))
            findings+=("Writable LD_LIBRARY_PATH")
        fi
    fi

    # NFS Shares Check
    echo -e "\n${COLORS[CYAN]}[*] NFS Shares:${COLORS[NC]}"
    if [ -f "/etc/exports" ]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^[^#] ]]; then
                echo -e "    ├── $line"
                if [[ "$line" =~ "no_root_squash" ]]; then
                    display_vulnerability "HIGH" "NFS no_root_squash" "NFS share with no_root_squash: $line"
                    ((STATS[HIGH_VULNS]++))
                    findings+=("NFS no_root_squash share found")
                fi
            fi
        done < "/etc/exports"
    fi

    # Display Summary
    print_section_header "System Enumeration Summary"
    echo -e "\nKey Findings:"
    if [ ${#findings[@]} -eq 0 ]; then
        echo -e "${COLORS[GREEN]}No significant privilege escalation vectors found${COLORS[NC]}"
    else
        for finding in "${findings[@]}"; do
            echo -e "${COLORS[RED]}• $finding${COLORS[NC]}"
        done
    fi

    echo -e "\nStatistics:"
    echo -e "• High Vulnerabilities: ${STATS[HIGH_VULNS]}"
    echo -e "• Medium Vulnerabilities: ${STATS[MEDIUM_VULNS]}"
    echo -e "• Total Issues Found: ${STATS[TOTAL_VULNS]}"

    echo -e "\nRecommendations:"
    echo -e "1. Update kernel to latest version"
    echo -e "2. Review and restrict sudo permissions"
    echo -e "3. Audit file permissions on sensitive files"
    echo -e "4. Check and remove unnecessary capabilities"
    echo -e "5. Audit NFS share configurations"
    echo -e "6. Monitor docker group membership"

    echo -e "\n${COLORS[CYAN]}Status: Completed system enumeration check${COLORS[NC]}"
    echo
}

check_user_permissions() {
    
    echo -e "\n${COLORS[BOLD]}[*] Initiating user permissions audit...${COLORS[NC]}\n"
    
    # Initialize counters and arrays
    local total_users=$(wc -l < /etc/passwd)
    local current_user=0
    local root_users=0
    local system_users=0
    local regular_users=0
    local no_password_users=0
    local suspicious_home=0
    declare -A user_findings
    
    echo -e "${COLORS[CYAN]}[⠙] Analyzing ${COLORS[BOLD]}$total_users${COLORS[NC]}${COLORS[CYAN]} user accounts...${COLORS[NC]}\n"
    
    # Check sudo configuration
    echo -e "${COLORS[BOLD]}Checking sudo configuration...${COLORS[NC]}"
    if [ -f "/etc/sudoers" ]; then
        local sudo_all_count=$(grep -E "^[^#]*ALL=\(ALL:ALL\) ALL" /etc/sudoers 2>/dev/null | wc -l)
        local sudo_nopasswd_count=$(grep -E "^[^#]*NOPASSWD: ALL" /etc/sudoers 2>/dev/null | wc -l)
        
        if [ $sudo_all_count -gt 0 ]; then
            display_vulnerability "HIGH" "Users with full sudo rights" "$sudo_all_count users found"
            ((STATS[HIGH_VULNS]++))
        fi
        if [ $sudo_nopasswd_count -gt 0 ]; then
            display_vulnerability "CRITICAL" "Users with passwordless sudo" "$sudo_nopasswd_count users found"
            ((STATS[HIGH_VULNS]++))
        fi
    fi
    
    # Main user analysis
    while IFS=: read -r user pass uid gid desc home shell; do
        ((current_user++))
        printf "\r${COLORS[CYAN]}[⠙] Progress: ${COLORS[BOLD]}%d/%d${COLORS[NC]} users analyzed" "$current_user" "$total_users"
        
        local user_issues=()
        
        # Check UID
        if [ "$uid" -eq 0 ]; then
            user_issues+=("ROOT_UID")
            ((root_users++))
            display_vulnerability "HIGH" "User with UID 0" "$user ($desc)"
            ((STATS[HIGH_VULNS]++))
        elif [ "$uid" -lt 1000 ]; then
            ((system_users++))
        else
            ((regular_users++))
        fi
        
        # Check password field
        if [[ "$pass" == "" || "$pass" == "*" || "$pass" == "!" ]]; then
            user_issues+=("NO_PASSWORD")
            ((no_password_users++))
        fi
        
        # Check home directory
        if [ -d "$home" ]; then
            # Check home directory permissions
            local home_perms=$(stat -c "%a" "$home" 2>/dev/null)
            if [ "$home_perms" -ge 755 ]; then
                user_issues+=("WORLD_READABLE_HOME")
            fi
            
            # Check for world-writable files in home
            local writable_files=$(find "$home" -type f -perm -2 2>/dev/null | wc -l)
            if [ "$writable_files" -gt 0 ]; then
                user_issues+=("WORLD_WRITABLE_FILES:$writable_files")
            fi
        else
            user_issues+=("MISSING_HOME")
        fi
        
        # Check for suspicious home directory location
        for risky_dir in "${!RISKY_DIRS[@]}"; do
            if [[ "$home" == "$risky_dir"* && "$user" != "root" ]]; then
                user_issues+=("SUSPICIOUS_HOME:${RISKY_DIRS[$risky_dir]}")
                ((suspicious_home++))
            fi
        done
        
        # Store findings if issues found
        if [ ${#user_issues[@]} -gt 0 ]; then
            user_findings[$user]="${user_issues[*]}"
            ((STATS[TOTAL_VULNS]++))
        fi
        
    done < /etc/passwd
    
    # Print Summary
    print_section_header "Summary of User's Permissions" 
    echo -e "${COLORS[BOLD]}Total users analyzed:${COLORS[NC]} $total_users"
    echo -e "${COLORS[RED]}${COLORS[BOLD]}Root users (UID 0):${COLORS[NC]} $root_users"
    echo -e "${COLORS[BLUE]}${COLORS[BOLD]}System users:${COLORS[NC]} $system_users"
    echo -e "${COLORS[CYAN]}${COLORS[BOLD]}Regular users:${COLORS[NC]} $regular_users"
    echo -e "${COLORS[YELLOW]}${COLORS[BOLD]}Users without password:${COLORS[NC]} $no_password_users"
    echo -e "${COLORS[MAGENTA]}${COLORS[BOLD]}Suspicious home locations:${COLORS[NC]} $suspicious_home"
    
    # Detailed Findings
    if [ ${#user_findings[@]} -gt 0 ]; then
        echo -e "\n${COLORS[BOLD]}Detailed User Security Issues:${COLORS[NC]}"
        echo "══════════════════════════"
        for user in "${!user_findings[@]}"; do
            echo -e "\n${COLORS[YELLOW]}${COLORS[BOLD]}User:${COLORS[NC]} $user"
            IFS=' ' read -ra issues <<< "${user_findings[$user]}"
            for issue in "${issues[@]}"; do
                case "${issue%%:*}" in
                    "ROOT_UID")
                        echo -e "${COLORS[RED]}  ⚠ Has root privileges (UID 0)${COLORS[NC]}"
                        ;;
                    "NO_PASSWORD")
                        echo -e "${COLORS[YELLOW]}  ● No password set${COLORS[NC]}"
                        ;;
                    "WORLD_READABLE_HOME")
                        echo -e "${COLORS[YELLOW]}  ● Home directory is world-readable${COLORS[NC]}"
                        ;;
                    "WORLD_WRITABLE_FILES")
                        count="${issue#*:}"
                        echo -e "${COLORS[RED]}  ⚠ Has $count world-writable files${COLORS[NC]}"
                        ;;
                    "MISSING_HOME")
                        echo -e "${COLORS[YELLOW]}  ● Home directory doesn't exist${COLORS[NC]}"
                        ;;
                    "SUSPICIOUS_HOME")
                        location="${issue#*:}"
                        echo -e "${COLORS[RED]}  ⚠ Suspicious home location: $location${COLORS[NC]}"
                        ;;
                esac
            done
        done
    fi
    
    # Security Recommendations
    echo -e "\n${COLORS[BOLD]}Security Recommendations:${COLORS[NC]}"
    echo "═════════════════════"
    echo "1. Regular User Management:"
    echo "   - Review and remove unnecessary user accounts"
    echo "   - Ensure all active accounts have secure passwords"
    echo "   - Regularly audit user permissions and group memberships"
    
    if [ $root_users -gt 1 ]; then
        echo -e "\n2. ${COLORS[RED]}Critical: Multiple Root Users${COLORS[NC]}"
        echo "   - Remove root privileges from non-essential accounts"
        echo "   - Audit all actions performed by root users"
    fi
    
    if [ $suspicious_home -gt 0 ]; then
        echo -e "\n3. ${COLORS[YELLOW]}Home Directory Security${COLORS[NC]}"
        echo "   - Relocate home directories to appropriate locations"
        echo "   - Review and fix directory permissions"
    fi
    
    echo -e "\n4. Best Practices:"
    echo "   - Implement password complexity requirements"
    echo "   - Set up file integrity monitoring"
    echo "   - Regular security audits of user activities"
    echo
}


check_file_permissions() {
    local total_dirs=5  # /etc, /bin, /sbin, /usr/bin, /usr/sbin
    local current_dir=0
    
    # ANSI color codes for better readability
    local RED='\033[0;31m'
    local YELLOW='\033[1;33m'
    local NC='\033[0m'  # No Color

    echo "=== Starting File Permission Security Check ==="
    echo "Timestamp: $(date)"
    echo

    for dir in /etc /bin /sbin /usr/bin /usr/sbin; do
        echo "Scanning directory: $dir ($(($current_dir * 100 / $total_dirs))% complete)"
        
        # Check world-writable files (original check)
        echo "Checking world-writable files..."
        find "$dir" -type f -perm -2 -ls 2>/dev/null | while read line; do
            display_vulnerability "MEDIUM" "World-writable file" "$line"
            ((STATS[MEDIUM_VULNS]++))
            ((STATS[TOTAL_VULNS]++))
        done

        # Check group-writable files
        echo "Checking group-writable files..."
        find "$dir" -type f -perm -20 ! -perm -2 -ls 2>/dev/null | while read line; do
            display_vulnerability "LOW" "Group-writable file" "$line"
            ((STATS[LOW_VULNS]++))
            ((STATS[TOTAL_VULNS]++))
        done

        # Check files with unusual permissions (not 644 or 755)
        echo "Checking for unusual permissions..."
        find "$dir" -type f ! -perm 644 ! -perm 755 ! -perm 500 -ls 2>/dev/null | while read line; do
            display_vulnerability "LOW" "Unusual file permissions" "$line"
            ((STATS[LOW_VULNS]++))
            ((STATS[TOTAL_VULNS]++))
        done

        # Check unowned or ungrouped files
        echo "Checking unowned files..."
        find "$dir" \( -nouser -o -nogroup \) -ls 2>/dev/null | while read line; do
            display_vulnerability "HIGH" "Unowned file" "$line"
            ((STATS[HIGH_VULNS]++))
            ((STATS[TOTAL_VULNS]++))
        done

        # Check for hidden files
        echo "Checking hidden files..."
        find "$dir" -name ".*" -type f -ls 2>/dev/null | while read line; do
            display_vulnerability "INFO" "Hidden file found" "$line"
        done

        ((current_dir++))
        echo "----------------------------------------"
    done

    # Display summary
    echo
    print_section_header "Security Scan Summary" 
    echo -e "${RED}High-risk issues found: ${STATS[HIGH_VULNS]}"
    echo -e "${YELLOW}Medium-risk issues found: ${STATS[MEDIUM_VULNS]}"
    echo -e "${NC}Low-risk issues found: ${STATS[LOW_VULNS]}"
    echo "Total issues found: ${STATS[TOTAL_VULNS]}"
    echo "Directories scanned: $total_dirs"
    echo "Scan completed at: $(date)"
    echo "=========================="
}

check_cron_jobs() {
    local total_users=$(wc -l < /etc/passwd)
    local current_user=0
    local CRON_DIRS=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.monthly" "/etc/cron.weekly")
    
    # ANSI color codes
    local RED='\033[0;31m'
    local YELLOW='\033[1;33m'
    local ORANGE='\033[0;33m'
    local NC='\033[0m'

    echo "=== Starting Cron Job Security Audit ==="
    echo "Timestamp: $(date)"
    echo

    # Check system-wide crontab
    echo "Checking system-wide crontab (/etc/crontab)..."
    if [ -f "/etc/crontab" ]; then
        # Check permissions on /etc/crontab
        local crontab_perms=$(stat -c "%a" /etc/crontab)
        if [ "$crontab_perms" != "644" ]; then
            display_vulnerability "HIGH" "Insecure permissions on /etc/crontab" "Current permissions: $crontab_perms (should be 644)"
            ((STATS[HIGH_VULNS]++))
        fi

        # Check for suspicious commands in system crontab
        while read -r line; do
            # Skip comments and empty lines
            [[ "$line" =~ ^#|^$ ]] && continue

            # Check for sensitive commands
            if echo "$line" | grep -qE "chmod|chown|sudo|su|wget|curl|nc|bash|perl|python|ruby|php|eval|exec"; then
                display_vulnerability "HIGH" "Potentially dangerous command in system crontab" "Command: $line"
                ((STATS[HIGH_VULNS]++))
            fi
        done < /etc/crontab
    fi

    # Check cron directories
    echo "Checking cron directories..."
    for cron_dir in "${CRON_DIRS[@]}"; do
        if [ -d "$cron_dir" ]; then
            # Check directory permissions
            local dir_perms=$(stat -c "%a" "$cron_dir")
            if [ "$dir_perms" != "755" ]; then
                display_vulnerability "HIGH" "Insecure permissions on cron directory" "$cron_dir: $dir_perms (should be 755)"
                ((STATS[HIGH_VULNS]++))
            fi

            # Check files in cron directories
            find "$cron_dir" -type f 2>/dev/null | while read -r cronfile; do
                # Check file permissions
                local file_perms=$(stat -c "%a" "$cronfile")
                if [ "$file_perms" != "644" ]; then
                    display_vulnerability "HIGH" "Insecure permissions on cron file" "$cronfile: $file_perms (should be 644)"
                    ((STATS[HIGH_VULNS]++))
                fi

                # Check for suspicious content
                while read -r line; do
                    # Skip comments and empty lines
                    [[ "$line" =~ ^#|^$ ]] && continue

                    # Check for world-writable paths
                    if echo "$line" | grep -qE "/tmp|/var/tmp|/dev/shm"; then
                        display_vulnerability "MEDIUM" "Cron job using world-writable directory" "File: $cronfile, Command: $line"
                        ((STATS[MEDIUM_VULNS]++))
                    fi

                    # Check for privilege escalation risks
                    if echo "$line" | grep -qE "chmod\s+([0-7]{4}|[+]x)|bash -i|>" ; then
                        display_vulnerability "CRITICAL" "Potential privilege escalation in cron job" "File: $cronfile, Command: $line"
                        ((STATS[CRITICAL_VULNS]++))
                    fi
                done < "$cronfile"
            done
        fi
    done

    # Check individual user crontabs
    echo "Checking user crontabs..."
    while IFS=: read -r user _; do
        echo -ne "Progress: [$(($current_user * 100 / $total_users))%]\r"
        
        # Skip system users
        if [ "$(id -u "$user" 2>/dev/null)" -ge 1000 ] 2>/dev/null; then
            crontab -u "$user" -l 2>/dev/null | while read -r line; do
                # Skip comments and empty lines
                [[ "$line" =~ ^#|^$ ]] && continue

                # Basic cron job logging
                display_vulnerability "LOW" "User cron job" "$user: $line"
                ((STATS[LOW_VULNS]++))

                # Check for suspicious commands
                if echo "$line" | grep -qE "chmod|chown|sudo|su|wget|curl|nc|bash -i|perl|python|ruby|php|eval|exec"; then
                    display_vulnerability "HIGH" "Suspicious command in user cron job" "$user: $line"
                    ((STATS[HIGH_VULNS]++))
                fi

                # Check for writable script paths
                local cmd_path=$(echo "$line" | awk '{print $6}' | grep -oE '^[^>&|]*')
                if [ -n "$cmd_path" ] && [ -f "$cmd_path" ]; then
                    local path_perms=$(stat -c "%a" "$cmd_path" 2>/dev/null)
                    if [ -n "$path_perms" ] && [ "$path_perms" -ge "666" ]; then
                        display_vulnerability "CRITICAL" "World-writable script in cron job" "$user: $cmd_path (permissions: $path_perms)"
                        ((STATS[CRITICAL_VULNS]++))
                    fi
                fi

                # Check for relative paths
                if echo "$line" | grep -qE '[^/\.]\.\.'; then
                    display_vulnerability "HIGH" "Relative path in cron job" "$user: $line"
                    ((STATS[HIGH_VULNS]++))
                fi
            done
        fi
        ((current_user++))
    done < /etc/passwd

    # Display summary
    echo
    print_section_header "Cron Security Audit Summary" 
    echo -e "${RED}Critical vulnerabilities: ${STATS[CRITICAL_VULNS]}"
    echo -e "${ORANGE}High-risk issues: ${STATS[HIGH_VULNS]}"
    echo -e "${YELLOW}Medium-risk issues: ${STATS[MEDIUM_VULNS]}"
    echo -e "${NC}Low-risk issues: ${STATS[LOW_VULNS]}"
    echo "Total users checked: $total_users"
    echo "Cron directories checked: ${#CRON_DIRS[@]}"
    echo "Scan completed at: $(date)"
    echo "=============================="
}


check_system_integrity() {
    # ANSI color codes
    local RED='\033[0;31m'
    local YELLOW='\033[1;33m'
    local BLUE='\033[0;34m'
    local NC='\033[0m'

    echo "=== Starting System Integrity Check ==="
    echo "Timestamp: $(date)"
    echo

    # Initialize counters for statistics
    local files_checked=0
    local packages_checked=0

    # Function to calculate percentage
    calc_percentage() {
        echo $(( $1 * 100 / $2 ))
    }

    # Check for required tools
    echo "Checking for integrity verification tools..."
    local tools_status=()
    
    # Debian/Ubuntu tools
    if command -v debsums >/dev/null 2>&1; then
        tools_status+=("debsums:found")
    else
        tools_status+=("debsums:missing")
    fi
    
    # RHEL/CentOS tools
    if command -v rpm >/dev/null 2>&1; then
        tools_status+=("rpm:found")
    else
        tools_status+=("rpm:missing")
    fi

    # Check for additional integrity tools
    for tool in aide tripwire samhain; do
        if command -v "$tool" >/dev/null 2>&1; then
            tools_status+=("$tool:found")
        else
            tools_status+=("$tool:missing")
        fi
    done

    # Debian/Ubuntu specific checks
    if command -v debsums >/dev/null 2>&1; then
        echo "Performing Debian/Ubuntu package integrity checks..."
        
        # Get total package count
        local total_files=$(dpkg-query -f '${binary:Package}\n' -W | wc -l)
        local current_file=0

        # Check package integrity
        while IFS= read -r line; do
            current_file=$((current_file + 1))
            echo -ne "Progress: [$(calc_percentage $current_file $total_files)%]\r"
            
            if [[ $line == *"FAILED"* ]]; then
                display_vulnerability "CRITICAL" "File Integrity Check Failed" "$line"
                ((STATS[CRITICAL_VULNS]++))
                ((STATS[TOTAL_VULNS]++))
            fi
            ((files_checked++))
        done < <(debsums -c 2>/dev/null)

        # Check for modified configuration files
        echo "Checking modified configuration files..."
        while IFS= read -r line; do
            if [[ $line == *"modified"* ]]; then
                display_vulnerability "MEDIUM" "Modified Configuration File" "$line"
                ((STATS[MEDIUM_VULNS]++))
                ((STATS[TOTAL_VULNS]++))
            fi
        done < <(debsums -e 2>/dev/null)
    fi

    # RPM-based system checks (RHEL/CentOS)
    if command -v rpm >/dev/null 2>&1; then
        echo "Performing RPM package integrity checks..."
        
        # Check package integrity
        while IFS= read -r line; do
            if [[ $line == *"FAILED"* || $line == *"missing"* ]]; then
                display_vulnerability "CRITICAL" "RPM File Integrity Check Failed" "$line"
                ((STATS[CRITICAL_VULNS]++))
                ((STATS[TOTAL_VULNS]++))
            fi
            ((files_checked++))
        done < <(rpm -Va 2>/dev/null)
    fi

    # Check critical system files
    echo "Checking critical system files..."
    local critical_files=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/group"
        "/etc/sudoers"
        "/etc/ssh/sshd_config"
        "/boot/grub/grub.cfg"
        "/etc/fstab"
    )

    for file in "${critical_files[@]}"; do
        if [ -f "$file" ]; then
            # Store original checksum
            local stored_sum=""
            local checksum_file="/var/lib/system-integrity/${file//\//_}.sha256"
            
            if [ -f "$checksum_file" ]; then
                stored_sum=$(cat "$checksum_file")
            fi
            
            # Calculate current checksum
            local current_sum=$(sha256sum "$file" | awk '{print $1}')
            
            # Check file permissions
            local perms=$(stat -c "%a" "$file")
            local owner=$(stat -c "%U:%G" "$file")
            
            # Compare checksums if stored sum exists
            if [ -n "$stored_sum" ] && [ "$stored_sum" != "$current_sum" ]; then
                display_vulnerability "CRITICAL" "Critical File Modified" "$file (checksum mismatch)"
                ((STATS[CRITICAL_VULNS]++))
                ((STATS[TOTAL_VULNS]++))
            fi
            
            # Check permissions
            case "$file" in
                "/etc/shadow")
                    if [ "$perms" != "640" ] && [ "$perms" != "600" ]; then
                        display_vulnerability "CRITICAL" "Incorrect Permissions" "$file ($perms, should be 640 or 600)"
                        ((STATS[CRITICAL_VULNS]++))
                    fi
                    ;;
                "/etc/passwd"|"/etc/group")
                    if [ "$perms" != "644" ]; then
                        display_vulnerability "HIGH" "Incorrect Permissions" "$file ($perms, should be 644)"
                        ((STATS[HIGH_VULNS]++))
                    fi
                    ;;
                *)
                    if [ "$perms" != "600" ] && [ "$perms" != "644" ]; then
                        display_vulnerability "MEDIUM" "Unusual Permissions" "$file ($perms)"
                        ((STATS[MEDIUM_VULNS]++))
                    fi
                    ;;
            esac
            ((files_checked++))
        fi
    done

    # Check for rootkits if rkhunter is available
    if command -v rkhunter >/dev/null 2>&1; then
        echo "Performing rootkit scan..."
        while IFS= read -r line; do
            if [[ $line == *"Warning"* ]]; then
                display_vulnerability "CRITICAL" "Possible Rootkit Detected" "$line"
                ((STATS[CRITICAL_VULNS]++))
                ((STATS[TOTAL_VULNS]++))
            fi
        done < <(rkhunter --check --skip-keypress --quiet)
    fi

    # Display summary
    echo
    print_section_header "System Integrity Check Summary" 
    echo -e "${RED}Critical vulnerabilities found: ${STATS[CRITICAL_VULNS]}"
    echo -e "${YELLOW}High-risk issues found: ${STATS[HIGH_VULNS]}"
    echo -e "${BLUE}Medium-risk issues found: ${STATS[MEDIUM_VULNS]}"
    echo "Total files checked: $files_checked"
    echo "Available integrity tools: $(printf '%s ' "${tools_status[@]}")"
    echo "Scan completed at: $(date)"
    echo "=============================="

    # Recommendations if issues found
    if [ ${STATS[TOTAL_VULNS]} -gt 0 ]; then
        echo
        echo "Recommendations:"
        echo "1. Verify all failed integrity checks manually"
        echo "2. Consider installing additional integrity checking tools"
        echo "3. Set up regular integrity monitoring"
        echo "4. Review and correct file permissions"
        echo "5. Consider implementing AIDE or Tripwire for continuous monitoring"
    fi
}


check_suspicious_processes() {
    echo -e "\n${COLORS[BLUE]}${COLORS[BOLD]}=== Suspicious Process Check ===${COLORS[NC]}\n"
    local findings=()
    
    echo -e "${COLORS[CYAN]}[*] System Load Analysis:${COLORS[NC]}"
    local load_average=$(uptime | awk -F'load average:' '{print $2}')
    echo -e "    ├── Current Load Average: $load_average"
    
    # Get total system memory
    local total_mem=$(free -m | awk '/^Mem:/{print $2}')
    echo -e "    └── Total System Memory: ${total_mem}MB"

    # Check for known malicious process names
    echo -e "\n${COLORS[CYAN]}[*] Scanning for Known Malicious Processes:${COLORS[NC]}"
    local suspicious_names=(
        "crypto" "miner" "monero" "xmrig" "stratum" 
        "kworker" "kdevtmpfsi" "kinsing" "Mining" 
        "backdoor" "rootkit" "pwkit" "sshd_" "http_"
    )
    
    # Network Connection Check
    echo -e "\n${COLORS[CYAN]}[*] Network Connection Analysis:${COLORS[NC]}"
    if command -v netstat >/dev/null 2>&1; then
        local suspicious_ports=(
            "6379" # Redis default
            "27017" # MongoDB default
            "3389" # RDP
            "4444" # Common malware
            "6666" # Common malware
            "8545" # Ethereum JSON-RPC
            "3333" # Common mining
            "14444" # Common mining
            "14433" # Common mining
        )
        
        for port in "${suspicious_ports[@]}"; do
            if netstat -tuln 2>/dev/null | grep -q ":$port"; then
                local proc_info=$(netstat -tulnp 2>/dev/null | grep ":$port")
                display_vulnerability "HIGH" "Suspicious Port" "Process listening on known suspicious port $port: $proc_info"
                ((STATS[HIGH_VULNS]++))
                findings+=("Suspicious port $port in use")
            fi
        done
    fi

    # Process Analysis
    echo -e "\n${COLORS[CYAN]}[*] Process Resource Usage Analysis:${COLORS[NC]}"
    echo -e "    ├── Checking CPU and Memory Usage"
    echo -e "    ├── Analyzing Process Relationships"
    echo -e "    └── Scanning for Suspicious Patterns\n"

    # Create temporary files for process information
    local temp_dir=$(mktemp -d)
    local ps_output="${temp_dir}/ps_output.txt"
    ps aux > "$ps_output"

    # Track parent-child relationships
    declare -A child_processes
    ps -ef | while read -r line; do
        local pid=$(echo "$line" | awk '{print $2}')
        local ppid=$(echo "$line" | awk '{print $3}')
        child_processes[$ppid]+="$pid "
    done

    # Process Analysis
    while IFS= read -r line; do
        local user=$(echo "$line" | awk '{print $1}')
        local pid=$(echo "$line" | awk '{print $2}')
        local cpu=$(echo "$line" | awk '{print $3}')
        local mem=$(echo "$line" | awk '{print $4}')
        local vsz=$(echo "$line" | awk '{print $5}')
        local rss=$(echo "$line" | awk '{print $6}')
        local cmd=$(echo "$line" | awk '{$1=$2=$3=$4=$5=$6=$7=$8=$9=$10=""; print $0}' | sed 's/^ *//')
        
        # Check high resource usage
        if (( $(echo "$cpu > 50.0" | bc -l) )); then
            display_vulnerability "MEDIUM" "High CPU Usage" "Process using ${cpu}% CPU: $cmd (PID: $pid, User: $user)"
            ((STATS[MEDIUM_VULNS]++))
            findings+=("High CPU usage: $cmd")
        fi
        
        if (( $(echo "$mem > 30.0" | bc -l) )); then
            display_vulnerability "MEDIUM" "High Memory Usage" "Process using ${mem}% Memory: $cmd (PID: $pid, User: $user)"
            ((STATS[MEDIUM_VULNS]++))
            findings+=("High memory usage: $cmd")
        fi

        # Check suspicious process names
        for suspicious in "${suspicious_names[@]}"; do
            if echo "$cmd" | grep -qi "$suspicious"; then
                display_vulnerability "HIGH" "Suspicious Process Name" "Potentially malicious process: $cmd (PID: $pid, User: $user)"
                ((STATS[HIGH_VULNS]++))
                findings+=("Suspicious process name: $cmd")
            fi
        done

        # Check for processes running as root
        if [ "$user" = "root" ]; then
            if echo "$cmd" | grep -qiE "nc|netcat|python|perl|ruby|bash|sh|ksh|csh|ncat|socat"; then
                display_vulnerability "HIGH" "Root Shell Process" "Shell/interpreter running as root: $cmd"
                ((STATS[HIGH_VULNS]++))
                findings+=("Root shell process: $cmd")
            fi
        fi

        # Check process age
        local process_start=$(ps -o lstart= -p "$pid" 2>/dev/null)
        if [ ! -z "$process_start" ]; then
            local start_seconds=$(date -d "$process_start" +%s 2>/dev/null)
            local current_seconds=$(date +%s)
            local age_hours=$(( (current_seconds - start_seconds) / 3600 ))
            
            if [ $age_hours -lt 1 ]; then
                echo -e "${COLORS[YELLOW]}[!] Recent Process Started: $cmd (Age: <1 hour)${COLORS[NC]}"
            fi
        fi

        # Check unusual parent-child relationships
        if [ ! -z "${child_processes[$pid]}" ]; then
            local child_count=$(echo "${child_processes[$pid]}" | wc -w)
            if [ $child_count -gt 10 ]; then
                display_vulnerability "MEDIUM" "Unusual Process Tree" "Process has unusual number of children ($child_count): $cmd"
                ((STATS[MEDIUM_VULNS]++))
                findings+=("Unusual process tree: $cmd")
            fi
        fi

    done < "$ps_output"

    # Check for hidden processes
    echo -e "\n${COLORS[CYAN]}[*] Hidden Process Detection:${COLORS[NC]}"
    local ps_pids=$(ps -ef | awk '{print $2}' | sort -n)
    local proc_pids=$(ls /proc/ | grep -E '^[0-9]+$' | sort -n)
    
    comm -13 <(echo "$ps_pids") <(echo "$proc_pids") | while read -r pid; do
        if [ -d "/proc/$pid" ]; then
            display_vulnerability "CRITICAL" "Hidden Process" "Process $pid is hidden from ps output"
            ((STATS[HIGH_VULNS]++))
            findings+=("Hidden process detected: $pid")
        fi
    done

    # Cleanup
    rm -rf "${temp_dir}"

    # Display Summary
    print_section_header "Process Check Summary"
    echo -e "\nKey Findings:"
    if [ ${#findings[@]} -eq 0 ]; then
        echo -e "${COLORS[GREEN]}No suspicious processes detected${COLORS[NC]}"
    else
        for finding in "${findings[@]}"; do
            echo -e "${COLORS[RED]}• $finding${COLORS[NC]}"
        done
    fi

    echo -e "\nStatistics:"
    echo -e "• Critical/High Risk Processes: ${STATS[HIGH_VULNS]}"
    echo -e "• Medium Risk Processes: ${STATS[MEDIUM_VULNS]}"
    echo -e "• Total Issues Found: ${STATS[TOTAL_VULNS]}"

    echo -e "\nRecommendations:"
    echo -e "1. Investigate processes with high resource usage"
    echo -e "2. Review all root-owned processes"
    echo -e "3. Check recently started processes"
    echo -e "4. Investigate processes listening on suspicious ports"
    echo -e "5. Monitor processes with unusual parent-child relationships"
    echo -e "6. Verify legitimacy of processes with suspicious names"

    echo -e "\n${COLORS[CYAN]}Status: Completed process analysis${COLORS[NC]}"
    echo
}
# Function to check for system updates
check_system_updates() {
    print_section_header "System Updates Analysis"
    echo -e "${COLORS[BLUE]}${COLORS[BOLD]}[*] Initiating comprehensive system updates check...${COLORS[NC]}\n"
    
    # Initialize counters
    local total_updates=0
    local security_updates=0
    local critical_updates=0
    local other_updates=0
    local kernel_updates=0
    local last_update=""
    declare -A vulnerable_packages
    
    # Check last system update time
    if [ -f "/var/log/apt/history.log" ]; then
        last_update=$(grep 'Start-Date' /var/log/apt/history.log | tail -n 1 | cut -d':' -f2-)
    elif [ -f "/var/log/yum.log" ]; then
        last_update=$(tail -n 1 "/var/log/yum.log" | cut -d' ' -f1,2)
    fi
    
    echo -e "${COLORS[CYAN]}[⠙] Checking package manager and system state...${COLORS[NC]}"
    
    # Function to parse debian security updates
    parse_debian_security() {
        local pkg="$1"
        local version="$2"
        if [[ "$pkg" =~ linux-(image|headers) ]]; then
            ((kernel_updates++))
            vulnerable_packages["$pkg"]="kernel|$version"
            display_vulnerability "CRITICAL" "Kernel Update Required" "$pkg ($version available)"
            ((STATS[HIGH_VULNS]++))
        elif [[ "$pkg" =~ ^(openssl|sudo|ssh|pam|ssl|tls|crypt) ]]; then
            ((security_updates++))
            vulnerable_packages["$pkg"]="security|$version"
            display_vulnerability "HIGH" "Security Package Update" "$pkg ($version available)"
            ((STATS[HIGH_VULNS]++))
        fi
    }
    
    # Function to parse RHEL/CentOS security updates
    parse_rhel_security() {
        local pkg="$1"
        local version="$2"
        local severity="$3"
        case "$severity" in
            *Critical*|*Important*)
                ((critical_updates++))
                vulnerable_packages["$pkg"]="critical|$version"
                display_vulnerability "CRITICAL" "Critical Security Update" "$pkg ($version available)"
                ((STATS[HIGH_VULNS]++))
                ;;
            *Moderate*)
                ((security_updates++))
                vulnerable_packages["$pkg"]="security|$version"
                display_vulnerability "MEDIUM" "Security Update Available" "$pkg ($version available)"
                ((STATS[MEDIUM_VULNS]++))
                ;;
        esac
    }
    
    # Check for updates based on package manager
    if command -v apt-get &> /dev/null; then
        echo -e "${COLORS[BLUE]}[*] Detected Debian-based system${COLORS[NC]}"
        
        # Update package lists
        echo -e "${COLORS[CYAN]}[⠙] Updating package lists...${COLORS[NC]}"
        sudo apt-get update &> /dev/null
        
        # Get security updates
        echo -e "${COLORS[CYAN]}[⠙] Checking for security updates...${COLORS[NC]}"
        while IFS= read -r line; do
            if [[ "$line" =~ ^Inst\ ([^\ ]+)\ \[([^]]+)\] ]]; then
                local pkg="${BASH_REMATCH[1]}"
                local version="${BASH_REMATCH[2]}"
                parse_debian_security "$pkg" "$version"
                ((total_updates++))
            fi
        done < <(apt list --upgradable 2>/dev/null)
        
    elif command -v yum &> /dev/null; then
        echo -e "${COLORS[BLUE]}[*] Detected RHEL-based system${COLORS[NC]}"
        
        # Check for security updates
        echo -e "${COLORS[CYAN]}[⠙] Checking for security updates...${COLORS[NC]}"
        while IFS= read -r line; do
            if [[ "$line" =~ ^([^\ ]+)\ +([^\ ]+)\ +([^\ ]+) ]]; then
                local pkg="${BASH_REMATCH[1]}"
                local version="${BASH_REMATCH[2]}"
                local severity="${BASH_REMATCH[3]}"
                parse_rhel_security "$pkg" "$version" "$severity"
                ((total_updates++))
            fi
        done < <(yum check-update --security 2>/dev/null)
        
    else
        display_vulnerability "MEDIUM" "Unknown Package Manager" "Unable to determine system package manager"
        ((STATS[MEDIUM_VULNS]++))
        return
    fi
    
    # Update statistics
    ((STATS[TOTAL_VULNS]+=total_updates))
    ((other_updates=total_updates-security_updates-critical_updates-kernel_updates))
    
    # Print Summary
    print_section_header "System Updates Summary"
    echo -e "${COLORS[BOLD]}Last System Update:${COLORS[NC]} $last_update"
    echo -e "${COLORS[BOLD]}Total Updates Available:${COLORS[NC]} $total_updates"
    echo -e "${COLORS[RED]}${COLORS[BOLD]}Critical Security Updates:${COLORS[NC]} $critical_updates"
    echo -e "${COLORS[RED]}${COLORS[BOLD]}Kernel Updates:${COLORS[NC]} $kernel_updates"
    echo -e "${COLORS[YELLOW]}${COLORS[BOLD]}Security Updates:${COLORS[NC]} $security_updates"
    echo -e "${COLORS[BLUE]}${COLORS[BOLD]}Other Updates:${COLORS[NC]} $other_updates"
    
    # Risk Assessment
    echo -e "\n${COLORS[BOLD]}Risk Assessment:${COLORS[NC]}"
    echo "═════════════════"
    if [ $critical_updates -gt 0 ] || [ $kernel_updates -gt 0 ]; then
        echo -e "${COLORS[RED]}${COLORS[BOLD]}[!] CRITICAL RISK - Immediate updates required${COLORS[NC]}"
        echo -e "${COLORS[RED]}    ▶ System has critical security updates pending${COLORS[NC]}"
    elif [ $security_updates -gt 0 ]; then
        echo -e "${COLORS[YELLOW]}${COLORS[BOLD]}[!] MEDIUM RISK - Security updates recommended${COLORS[NC]}"
        echo -e "${COLORS[YELLOW]}    ▶ System has security updates pending${COLORS[NC]}"
    else
        echo -e "${COLORS[GREEN]}${COLORS[BOLD]}[✓] LOW RISK - System is relatively up to date${COLORS[NC]}"
    fi
    
    # Detailed Package Information
    if [ ${#vulnerable_packages[@]} -gt 0 ]; then
        echo -e "\n${COLORS[BOLD]}Detailed Package Information:${COLORS[NC]}"
        echo "═══════════════════════════"
        for pkg in "${!vulnerable_packages[@]}"; do
            IFS='|' read -r type version <<< "${vulnerable_packages[$pkg]}"
            case "$type" in
                "kernel")
                    echo -e "${COLORS[RED]}[!] ${COLORS[BOLD]}$pkg${COLORS[NC]} - Kernel Update"
                    echo -e "    ▶ Version: $version"
                    echo -e "    ▶ Priority: Critical - System Security Impact"
                    ;;
                "critical")
                    echo -e "${COLORS[RED]}[!] ${COLORS[BOLD]}$pkg${COLORS[NC]} - Critical Security Update"
                    echo -e "    ▶ Version: $version"
                    echo -e "    ▶ Priority: High - Immediate Action Required"
                    ;;
                "security")
                    echo -e "${COLORS[YELLOW]}[!] ${COLORS[BOLD]}$pkg${COLORS[NC]} - Security Update"
                    echo -e "    ▶ Version: $version"
                    echo -e "    ▶ Priority: Medium - Update Recommended"
                    ;;
            esac
        done
    fi
    
    # Recommendations
    echo -e "\n${COLORS[BOLD]}Security Recommendations:${COLORS[NC]}"
    echo "════════════════════════"
    echo -e "1. ${COLORS[BOLD]}Update Schedule:${COLORS[NC]}"
    echo "   - Implement regular update schedule"
    echo "   - Prioritize security and kernel updates"
    echo "   - Consider automatic security updates"
    
    echo -e "\n2. ${COLORS[BOLD]}Testing Protocol:${COLORS[NC]}"
    echo "   - Test updates in staging environment first"
    echo "   - Create system backup before major updates"
    echo "   - Document any update-related issues"
    
    echo -e "\n3. ${COLORS[BOLD]}Monitoring:${COLORS[NC]}"
    echo "   - Monitor security advisories"
    echo "   - Set up alerts for critical updates"
    echo "   - Keep update logs for audit purposes"
    
    if [ $total_updates -eq 0 ]; then
        echo -e "\n${COLORS[GREEN]}${COLORS[BOLD]}[✓] System is up to date${COLORS[NC]}"
    fi
    
    echo
}

monitor_suspicious_processes() {
    local total_processes=$(ps aux | wc -l)
    local current_process=0
    
    # ANSI color codes
    local RED='\033[0;31m'
    local YELLOW='\033[1;33m'
    local BLUE='\033[0;34m'
    local NC='\033[0m'

    echo "=== Starting Process and Network Monitor ==="
    echo "Timestamp: $(date)"
    echo

    # Function to get process command line arguments
    get_process_cmdline() {
        cat "/proc/$1/cmdline" 2>/dev/null | tr '\0' ' ' || echo "N/A"
    }

    # Function to check for hidden processes
    check_hidden_processes() {
        local ps_pids=$(ps -ef | awk '{print $2}' | sort -n)
        local proc_pids=$(ls /proc | grep -E '^[0-9]+$' | sort -n)
        
        comm -13 <(echo "$ps_pids") <(echo "$proc_pids") | while read pid; do
            if [ -d "/proc/$pid" ]; then
                local cmdline=$(get_process_cmdline "$pid")
                display_vulnerability "CRITICAL" "Hidden Process Detected" "PID: $pid, Command: $cmdline"
                ((STATS[CRITICAL_VULNS]++))
                ((STATS[TOTAL_VULNS]++))
            fi
        done
    }

    echo "Checking for suspicious processes..."

    # Check for processes running as root with high resources
    ps aux | awk '$1=="root" && ($3>50.0 || $4>50.0)' | while read line; do
        display_vulnerability "HIGH" "High Resource Root Process" "$line"
        ((STATS[HIGH_VULNS]++))
        ((STATS[TOTAL_VULNS]++))
    done

    # Check for processes with unusual parent processes
    ps axo pid,ppid,user,pcpu,pmem,comm | while read pid ppid user cpu mem comm; do
        # Skip header
        [[ "$pid" == "PID" ]] && continue
        
        # Check if parent process exists and is valid
        if [ "$ppid" != "1" ] && [ ! -e "/proc/$ppid" ]; then
            display_vulnerability "HIGH" "Orphaned Process" "PID: $pid, PPID: $ppid, User: $user, Command: $comm"
            ((STATS[HIGH_VULNS]++))
            ((STATS[TOTAL_VULNS]++))
        fi

        # Check for unusual process names
        if echo "$comm" | grep -qE '[[:space:]]|\$|`|\\|\|'; then
            display_vulnerability "HIGH" "Suspicious Process Name" "PID: $pid, Command: $comm"
            ((STATS[HIGH_VULNS]++))
            ((STATS[TOTAL_VULNS]++))
        fi
    done

    # Check for processes without binary
    local processes_without_binary=$(ps aux | awk '$11=="?"' | wc -l)
    ps aux | awk '$11=="?"' | while read line; do
        local pid=$(echo "$line" | awk '{print $2}')
        local cmdline=$(get_process_cmdline "$pid")
        display_vulnerability "MEDIUM" "Process Without Binary" "$line\nCommand line: $cmdline"
        ((STATS[MEDIUM_VULNS]++))
        ((STATS[TOTAL_VULNS]++))
    done

    # Check for processes running from temporary directories
    ps aux | grep -E '/tmp/|/var/tmp/|/dev/shm/' | grep -v grep | while read line; do
        display_vulnerability "HIGH" "Process Running from Temporary Directory" "$line"
        ((STATS[HIGH_VULNS]++))
        ((STATS[TOTAL_VULNS]++))
    done

    # Network Checks
    echo "Performing network checks..."

    # Check for listening ports
    if command -v ss >/dev/null 2>&1; then
        # Use ss command if available (more modern)
        local listening_ports=$(ss -tulpn | grep LISTEN | wc -l)
        ss -tulpn | grep LISTEN | while read line; do
            local port=$(echo "$line" | awk '{print $5}' | awk -F: '{print $NF}')
            local process=$(echo "$line" | awk '{print $7}')
            
            # Check for well-known ports used by non-root
            if [ "$port" -lt 1024 ]; then
                local pid=$(echo "$process" | cut -d'=' -f2 | cut -d',' -f1)
                local user=$(ps -o user= -p "$pid" 2>/dev/null)
                if [ "$user" != "root" ]; then
                    display_vulnerability "CRITICAL" "Non-root Process on Privileged Port" "$line"
                    ((STATS[CRITICAL_VULNS]++))
                    ((STATS[TOTAL_VULNS]++))
                fi
            fi
            
            # Check for suspicious ports
            case "$port" in
                4444|5555|6666|6667|6697|8080|8443|9001|9050)
                    display_vulnerability "HIGH" "Suspicious Port" "$line (Known malicious port)"
                    ((STATS[HIGH_VULNS]++))
                    ((STATS[TOTAL_VULNS]++))
                    ;;
                *)
                    display_vulnerability "LOW" "Listening Port" "$line"
                    ((STATS[LOW_VULNS]++))
                    ((STATS[TOTAL_VULNS]++))
                    ;;
            esac
        done
    else
        # Fallback to netstat
        local listening_ports=$(netstat -tulpn 2>/dev/null | grep LISTEN | wc -l)
        netstat -tulpn 2>/dev/null | grep LISTEN | while read line; do
            local port=$(echo "$line" | awk '{print $4}' | awk -F: '{print $NF}')
            local process=$(echo "$line" | awk '{print $7}')
            
            # Similar checks as above
            if [ "$port" -lt 1024 ]; then
                local pid=$(echo "$process" | cut -d'/' -f1)
                local user=$(ps -o user= -p "$pid" 2>/dev/null)
                if [ "$user" != "root" ]; then
                    display_vulnerability "CRITICAL" "Non-root Process on Privileged Port" "$line"
                    ((STATS[CRITICAL_VULNS]++))
                    ((STATS[TOTAL_VULNS]++))
                fi
            fi
            
            case "$port" in
                4444|5555|6666|6667|6697|8080|8443|9001|9050)
                    display_vulnerability "HIGH" "Suspicious Port" "$line (Known malicious port)"
                    ((STATS[HIGH_VULNS]++))
                    ((STATS[TOTAL_VULNS]++))
                    ;;
                *)
                    display_vulnerability "LOW" "Listening Port" "$line"
                    ((STATS[LOW_VULNS]++))
                    ((STATS[TOTAL_VULNS]++))
                    ;;
            esac
        done
    fi

    # Check for unusual network connections
    if command -v ss >/dev/null 2>&1; then
        ss -antup | grep ESTABLISHED | while read line; do
            local remote_addr=$(echo "$line" | awk '{print $5}')
            # Check for suspicious remote addresses
            if echo "$remote_addr" | grep -qE '(^10\.|^172\.16\.|^192\.168\.)'; then
                continue  # Skip private networks
            fi
            display_vulnerability "MEDIUM" "External Connection" "$line"
            ((STATS[MEDIUM_VULNS]++))
            ((STATS[TOTAL_VULNS]++))
        done
    fi

    # Check for processes with open ports but no binary
    ps aux | awk '$11=="?"' | while read line; do
        local pid=$(echo "$line" | awk '{print $2}')
        if lsof -i -P -n -p "$pid" 2>/dev/null | grep -q LISTEN; then
            display_vulnerability "HIGH" "No-Binary Process with Open Port" "$line"
            ((STATS[HIGH_VULNS]++))
            ((STATS[TOTAL_VULNS]++))
        fi
    done

    # Check for hidden processes
    check_hidden_processes

    # Display summary
    print_section_header "Process and Network Monitor Summary" 
    echo -e "${RED}Critical vulnerabilities found: ${STATS[CRITICAL_VULNS]}"
    echo -e "${YELLOW}High-risk issues found: ${STATS[HIGH_VULNS]}"
    echo -e "${BLUE}Medium-risk issues found: ${STATS[MEDIUM_VULNS]}"
    echo "Total processes checked: $total_processes"
    echo "Processes without binary: $processes_without_binary"
    echo "Listening ports: $listening_ports"
    echo "Scan completed at: $(date)"
    echo "=============================="

    # Recommendations if issues found
    if [ ${STATS[TOTAL_VULNS]} -gt 0 ]; then
        echo
        echo "Recommendations:"
        echo "1. Investigate all processes running as root with high resource usage"
        echo "2. Review processes running from temporary directories"
        echo "3. Audit all listening ports, especially those below 1024"
        echo "4. Investigate processes without associated binaries"
        echo "5. Monitor external connections for suspicious activity"
        echo "6. Consider implementing process whitelisting"
    fi
}

# Basic vulnerability scanner

basic_vulnerability_scan() {

    local total_checks=3
    local current_check=0
    local vulnerabilities_found=0

    declare -A scan_results
    # Check SSH config
    ((current_check++))
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "PermitRootLogin yes" /etc/ssh/sshd_config; then
            echo "DEBUG: SSH Root Login Allowed"
            scan_results["ssh"]="VULNERABLE: Root login is currently allowed"
            display_vulnerability "HIGH" "SSH Root Login Allowed" "/etc/ssh/sshd_config"
            ((STATS[HIGH_VULNS]++))
            ((STATS[TOTAL_VULNS]++))
            ((vulnerabilities_found++))
        else
            scan_results["ssh"]="SECURE: Root login is properly disabled"
        fi
    else
        scan_results["ssh"]="INFO: SSH configuration file not found"
    fi
    echo "[✓] SSH configuration check completed"
    echo
      # Update progress (1 out of 3 checks done)

    # Check world-writable files
    ((current_check++))
    world_writable=$(find /etc /bin /sbin /usr/bin /usr/sbin -type f -perm -2 -ls 2>/dev/null)
    world_writable_count=$(echo "$world_writable" | grep -v "^$" | wc -l)
    if [ "$world_writable_count" -gt 0 ]; then
        echo "DEBUG: World-Writable Files Found: $world_writable_count"
        scan_results["world_writable"]="VULNERABLE: $world_writable_count world-writable files found"
        display_vulnerability "MEDIUM" "World-Writable Files" "$world_writable_count world-writable files found in important directories"
        ((STATS[TOTAL_VULNS]+=world_writable_count))
        ((STATS[MEDIUM_VULNS]+=world_writable_count))
        echo "DEBUG: STATS[MEDIUM_VULNS]=${STATS[MEDIUM_VULNS]}"
        echo "DEBUG: STATS[TOTAL_VULNS]=${STATS[TOTAL_VULNS]}"
        ((vulnerabilities_found+=world_writable_count))
    else
        scan_results["world_writable"]="SECURE: No world-writable files found in system directories"
    fi
    echo "[✓] World-writable files check completed"
    echo
      # Update progress (2 out of 3 checks done)
    ((current_check++))
    # Check Shellshock vulnerability
    if [ -x "$(command -v bash)" ]; then
        if bash -c "env x='() { :;}; echo vulnerable' bash -c 'echo test'" | grep -q vulnerable; then
            scan_results["shellshock"]="VULNERABLE: System is affected by Shellshock"
            display_vulnerability "CRITICAL" "Shellshock Vulnerability" "System is vulnerable to CVE-2014-6271"
            ((STATS[HIGH_VULNS]++))
            ((STATS[TOTAL_VULNS]++))
            ((vulnerabilities_found++))
        else
            scan_results["shellshock"]="SECURE: System is not affected by Shellshock"
        fi
    else
        scan_results["shellshock"]="INFO: Bash not found, Shellshock check skipped"
    fi
    echo "[✓] Shellshock vulnerability check completed"
    echo

    print_section_header "Basic Vuln Scan Summary" 
    echo
    echo "Checks Performed: $total_checks"
    echo "Issues Found: $vulnerabilities_found"
    echo
    echo "Detailed Results:"
    echo "----------------"
    echo "1. SSH Configuration:"
    echo "   ${scan_results["ssh"]}"
    echo
    echo "2. World-Writable Files:"
    echo "   ${scan_results["world_writable"]}"
    echo
    echo "3. Shellshock Vulnerability:"
    echo "   ${scan_results["shellshock"]}"
      # Update progress (3 out of 3 checks done)
    echo

    if [ $vulnerabilities_found -gt 0 ]; then
        echo "Recommendations:"
        echo "---------------"
        if [[ "${scan_results["ssh"]}" == *"VULNERABLE"* ]]; then
            echo "- Disable SSH root login by setting 'PermitRootLogin no' in /etc/ssh/sshd_config"
        fi
        if [[ "${scan_results["world_writable"]}" == *"VULNERABLE"* ]]; then
            echo "- Review and restrict permissions on world-writable files"
            echo "- Use 'chmod' to remove write permissions for 'others'"
        fi
        if [[ "${scan_results["shellshock"]}" == *"VULNERABLE"* ]]; then
            echo "- Update bash package immediately"
            echo "- Contact system administrator for immediate patching"
        fi
    else
        echo "[✓] No vulnerabilities were found in this scan"
        echo "    However, regular security audits are recommended"
    fi
    echo
}


# Function to check for open ports
check_open_ports() {
    local port_checker="netstat"
    local port_list=""
    [ ! -x "$(command -v netstat)" ] && [ -x "$(command -v ss)" ] && port_checker="ss"

    local open_ports=0
    if [ "$port_checker" = "netstat" ]; then
        port_list=$(netstat -tuln | grep LISTEN | awk '{print $4}' | awk -F: '{print $NF}' | sort -n | uniq)
        open_ports=$(echo "$port_list" | wc -l)
    else
        port_list=$(ss -tuln | grep LISTEN | awk '{print $5}' | awk -F: '{print $NF}' | sort -n | uniq)
        open_ports=$(echo "$port_list" | wc -l)
    fi

    print_section_header "Port Scan Summary" 
    echo "- Detection Method: $port_checker"
    echo "- Total Open Ports: $open_ports"

    if [ "$open_ports" -gt 0 ]; then
        echo "- Open Ports List:"
        while IFS= read -r port; do
            # Get service name if possible
            local service=$(grep -w "$port/tcp" /etc/services 2>/dev/null | head -1 | awk '{print $1}' || echo "unknown")
            echo "  └─ Port $port ($service)"
        done <<< "$port_list"
        
        if [ "$open_ports" -gt 10 ]; then
            echo
            echo "[!] SECURITY ALERT: High number of open ports detected"
            echo "    This might increase the attack surface of your system."
            display_vulnerability "MEDIUM" "Open Ports" "$open_ports ports detected - Consider closing unnecessary ports"
            ((STATS[MEDIUM_VULNS]++))
            ((STATS[TOTAL_VULNS]++))
        else
            echo
            echo "[i] NOTICE: The number of open ports is within normal range"
            echo "    However, it's recommended to regularly review and close unnecessary ports"
        fi
    else
        echo "- No open ports detected"
        echo
        echo "[✓] SECURE: No open ports found on the system"
    fi
    
    # Simulate progress for this check
    
    echo
}


# Function to check firewall configuration
check_firewall_config() {
    echo -e "\n${COLORS[BLUE]}${COLORS[BOLD]}=== Firewall Configuration Check ===${COLORS[NC]}\n"
    
    local firewall_found=false
    local details=()
    
    # Check UFW
    if command -v ufw &> /dev/null; then
        firewall_found=true
        echo -e "${COLORS[CYAN]}[*] UFW Firewall Detection:${COLORS[NC]}"
        
        # Check UFW status
        if sudo ufw status > /dev/null 2>&1; then
            local ufw_status=$(sudo ufw status)
            if echo "$ufw_status" | grep -q "Status: active"; then
                echo -e "${COLORS[GREEN]}${COLORS[BOLD]}[✓] UFW firewall is active${COLORS[NC]}"
                
                # Check UFW rules
                local rule_count=$(echo "$ufw_status" | grep -c "ALLOW\|DENY\|REJECT")
                echo -e "    ├── Found $rule_count firewall rules"
                
                # Check default policies
                local default_policies=$(sudo ufw status verbose | grep "Default:")
                echo -e "    ├── Default policies:"
                echo "$default_policies" | sed 's/^/    │   /'
                
                # Check listening ports
                echo -e "    └── Listening ports:"
                netstat -tulpn 2>/dev/null | grep "LISTEN" | sed 's/^/        /' || echo "        Unable to fetch listening ports"
                
                details+=("UFW: Active with $rule_count rules")
            else
                display_vulnerability "HIGH" "Firewall Inactive" "UFW firewall is installed but not active"
                echo -e "    └── ${COLORS[RED]}Recommendation: Enable UFW with 'sudo ufw enable'${COLORS[NC]}"
                ((STATS[HIGH_VULNS]++))
                ((STATS[TOTAL_VULNS]++))
                details+=("UFW: Installed but inactive")
            fi
        else
            display_vulnerability "HIGH" "UFW Access" "Unable to check UFW status - permission denied"
            ((STATS[HIGH_VULNS]++))
            ((STATS[TOTAL_VULNS]++))
            details+=("UFW: Permission denied")
        fi
    fi
    
    # Check iptables
    if command -v iptables &> /dev/null; then
        firewall_found=true
        echo -e "\n${COLORS[CYAN]}[*] IPTables Detection:${COLORS[NC]}"
        
        if sudo iptables -L > /dev/null 2>&1; then
            local iptables_rules=$(sudo iptables -L -v -n)
            
            # Check default policies
            local input_policy=$(echo "$iptables_rules" | grep "Chain INPUT" | awk '{print $4}')
            local forward_policy=$(echo "$iptables_rules" | grep "Chain FORWARD" | awk '{print $4}')
            local output_policy=$(echo "$iptables_rules" | grep "Chain OUTPUT" | awk '{print $4}')
            
            echo -e "    ├── Default Policies:"
            echo -e "    │   ├── INPUT: $input_policy"
            echo -e "    │   ├── FORWARD: $forward_policy"
            echo -e "    │   └── OUTPUT: $output_policy"
            
            # Check rule counts
            local input_rules=$(echo "$iptables_rules" | grep -c "Chain INPUT")
            local forward_rules=$(echo "$iptables_rules" | grep -c "Chain FORWARD")
            local output_rules=$(echo "$iptables_rules" | grep -c "Chain OUTPUT")
            
            echo -e "    ├── Rule Counts:"
            echo -e "    │   ├── INPUT: $input_rules rules"
            echo -e "    │   ├── FORWARD: $forward_rules rules"
            echo -e "    │   └── OUTPUT: $output_rules rules"
            
            if [ "$input_policy" = "ACCEPT" ]; then
                display_vulnerability "HIGH" "Firewall Policy" "iptables INPUT chain policy is set to ACCEPT"
                echo -e "    └── ${COLORS[RED]}Recommendation: Set INPUT policy to DROP and explicitly allow needed traffic${COLORS[NC]}"
                ((STATS[HIGH_VULNS]++))
                ((STATS[TOTAL_VULNS]++))
                details+=("IPTables: INPUT policy ACCEPT - security risk")
            else
                echo -e "${COLORS[GREEN]}${COLORS[BOLD]}[✓] iptables appears to be properly configured${COLORS[NC]}"
                details+=("IPTables: Properly configured")
            fi
        else
            display_vulnerability "HIGH" "IPTables Access" "Unable to check iptables rules - permission denied"
            ((STATS[HIGH_VULNS]++))
            ((STATS[TOTAL_VULNS]++))
            details+=("IPTables: Permission denied")
        fi
    fi
    
    # Check if no firewall was found
    if ! $firewall_found; then
        display_vulnerability "HIGH" "No Firewall" "No recognized firewall (ufw/iptables) found on the system"
        echo -e "    └── ${COLORS[RED]}Recommendation: Install and configure either UFW or iptables${COLORS[NC]}"
        ((STATS[HIGH_VULNS]++))
        ((STATS[TOTAL_VULNS]++))
        details+=("No firewall detected")
    fi
    
    # Display Summary
    print_section_header "Firewall Check Summary"
    echo -e "Findings:"
    for detail in "${details[@]}"; do
        echo -e "  • $detail"
    done
    
    # Add recommendations based on findings
    if [ ${#details[@]} -gt 0 ]; then
        echo -e "\nRecommendations:"
        echo -e "  1. Ensure at least one firewall (UFW or iptables) is active"
        echo -e "  2. Configure default policies to DROP for incoming traffic"
        echo -e "  3. Allow only necessary incoming ports"
        echo -e "  4. Regularly audit firewall rules"
        echo -e "  5. Consider implementing fail2ban for additional protection"
    fi
    
    echo -e "\n${COLORS[CYAN]}Status: Completed firewall configuration check${COLORS[NC]}"
    echo
}

 # Track current task progress


# Enhanced progress bar with percentage and ETA

show_progress() {
    local current=$1
    local total=$2
    local width=$progress_width
    local percentage=$((current * 100 / total))
    local filled=$((width * current / total))
    local empty=$((width - filled))
    local elapsed=$((SECONDS - start_time))
    local eta=$(( elapsed * (total - current) / current ))

    # Clear the current line
    printf "\r"
    
    # Create the progress bar
    printf "[${COLORS[CYAN]}"
    printf "%${filled}s" | tr ' ' '█'
    printf "${COLORS[NC]}"
    printf "%${empty}s" | tr ' ' '░'
    printf "] %3d%% " "$percentage"
    
    # Add timing information
    printf "(%d/%d) " "$current" "$total"
    printf "ETA: %02d:%02d" "$((eta/60))" "$((eta%60))"
    
    # Force output flush
    printf "\n"
}

for count in $(seq 1 $total_tasks); do
    sleep 0.1  # Simulate some work (replace this with actual tasks)
    show_progress $count $total_tasks
done
printf "\n"

# Enhanced spinner with message and subprocess monitoring
spinner() {
    local pid=$1
    local message=$2
    local spin_chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    
    tput civis  # Hide cursor
    
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i + 1) % ${#spin_chars} ))
        printf "\r${COLORS[BOLD]}[${COLORS[CYAN]}%s${COLORS[NC]}${COLORS[BOLD]}] %s " "${spin_chars:$i:1}" "$message"
        sleep 0.1
    done
    
    wait $pid
    local exit_status=$?
    
    tput cnorm  # Show cursor
    
    if [ $exit_status -eq 0 ]; then
        printf "\r${COLORS[BOLD]}[${COLORS[GREEN]}✓${COLORS[NC]}${COLORS[BOLD]}]Finished %s${COLORS[NC]}\n" "$message"
        #printf "${COLORS[GREEN]}Finished %s${COLORS[NC]}\n" "$message"
    else
        printf "\r${COLORS[BOLD]}[${COLORS[RED]}✗${COLORS[NC]}${COLORS[BOLD]}] %s failed${COLORS[NC]}\n" "$message"
    fi
    
    return $exit_status
}



# Function to handle partial results in case of interruption
generate_partial_report() {
    local partial_report="${CONFIG[REPORT_DIR]}/partial_report.md"

    echo -e "# Partial Audit Report (Interrupted)\n" > "$partial_report"
    echo -e "## Completed Checks: ${STATS[CHECKS_COMPLETED]}\n" >> "$partial_report"
    echo -e "## Failed Checks: ${STATS[CHECKS_FAILED]}\n" >> "$partial_report"
    echo -e "## Findings So Far\n" >> "$partial_report"

    # Add any collected findings
    if [ -f "${CONFIG[MARKDOWN_REPORT]}" ]; then
        cat "${CONFIG[MARKDOWN_REPORT]}" >> "$partial_report"
    fi
}

# Cleanup function


# Function to check dependencies
check_dependencies() {
    local dependencies=("find" "grep" "awk" "sed" "ss" "systemctl" "debsums" "bc")
    local missing_deps=()

    echo -e "
${COLORS[BOLD]}${COLORS[CYAN]}[+] Checking dependencies...${COLORS[NC]}"

    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done

    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${COLORS[BOLD]}${COLORS[RED]}[!] Missing dependencies: ${missing_deps[*]}${COLORS[NC]}"
        echo -e "${COLORS[BOLD]}Please install the missing dependencies and try again${COLORS[NC]}"
        exit 1
    fi

    echo -e "${COLORS[BOLD]}${COLORS[GREEN]}[✓] All dependencies satisfied${COLORS[NC]}"
}

# Print animated banner
print_banner() {
    
    echo -e "${COLORS[CYAN]}${COLORS[BOLD]}
     █████╗ ██╗██████╗ ███████╗██████╗
    ██╔══██╗██║██╔══██╗██╔════╝██╔══██╗
    ███████║██║██║  ██║█████╗  ██████╔╝
    ██╔══██║██║██║  ██║██╔══╝  ██╔══██╗
    ██║  ██║██║██████╔╝███████╗██║  ██║
    ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝${COLORS[NC]}"

    echo -e "\n${COLORS[BOLD]}${COLORS[CYAN]}Advanced Intrusion Detection & Enhanced Review Tool${COLORS[NC]}"
    echo -e "${COLORS[BOLD]}${COLORS[GREY]}Version 1.1 - Developed fby Triada${COLORS[NC]}\n"

    # Additional Author and Tool Info
    echo -e "${COLORS[BOLD]}${COLORS[CYAN]}
Author       : Elishah
Tool         : Aider - Advanced Intrusion Detection and Enhanced Review Tool
Usage        : ./aider.sh [options]
Description  : Aider performs a comprehensive security audit on Unix-based systems,
              : focusing on system misconfigurations and vulnerabilities.
              : It generates detailed reports and compares results with
              : historical data to track security improvements over time.${COLORS[NC]}"

     echo -e "\n${COLORS[BLUE_BOLD]}==============( System Information )=================${COLORS[NC]}"
     echo -e "${COLORS[GREY]}
    * Hostname       : $(hostname)
    * OS             : $(cat /etc/os-release 2>/dev/null | grep "PRETTY_NAME" | cut -d'"' -f2)
    * Kernel         : $(uname -r)
    * Architecture   : $(uname -m)
    * CPU            : $(grep "model name" /proc/cpuinfo | head -n1 | cut -d':' -f2 | sed 's/^[ \t]*//')
    * Date           : $(date)
    ${COLORS[NC]}"
}


# Initialize configuration
init_config() {
    # Set up directories
CONFIG[REPORT_DIR]="/tmp/aider_test_results"
    CONFIG[HTML_REPORT]="${CONFIG[REPORT_DIR]}/report.html"
    CONFIG[JSON_REPORT]="${CONFIG[REPORT_DIR]}/report.json"
    CONFIG[MARKDOWN_REPORT]="${CONFIG[REPORT_DIR]}/report.md"
    CONFIG[LOG_FILE]="${CONFIG[REPORT_DIR]}/audit.log"

    # Create directories
    mkdir -p "${CONFIG[REPORT_DIR]}" "${CONFIG[HISTORICAL_DIR]}"

    # Initialize log file
    touch "${CONFIG[LOG_FILE]}"

    # Set up error handling
    #set -o errexit
    set -o nounset
    set -o pipefail
}

# Initialize environment
initialize_environment() {
    
    init_config
    
    check_dependencies
    
    print_banner
    
}

# Main execution function with improved error handling
main() {
      # Track start time for ETA calculation
    if [[ $EUID -ne 0 ]]; then
        echo -e "${COLORS[RED]}${COLORS[BOLD]}[!] This script requires root privileges. Please run with sudo.${COLORS[NC]}"
        exit 1
    fi

    if [[ ! -d "${CONFIG[REPORT_DIR]}" ]]; then
        mkdir -p "${CONFIG[REPORT_DIR]}"
        echo -e "${COLORS[GREEN]}[+] Report directory created at: ${CONFIG[REPORT_DIR]}${COLORS[NC]}"
    else
        echo -e "${COLORS[YELLOW]}[i] Report Summary will be saved at: ${CONFIG[REPORT_DIR]}${COLORS[NC]}"
    fi
    
    # Initialize log file
    sudo touch "${CONFIG[LOG_FILE]}"
    
    total_tasks=12  # Total number of tasks
    current_task=0  # Reset progress
    start_time=$SECONDS  # Start the timer


    

    parse_arguments "$@"
    echo "Starting main process..."
    initialize_environment
    

    echo -e "\n${COLORS[BLUE_BOLD]}==============( Starting Security Audit )=================${COLORS[NC]}"
    echo -e "${COLORS[BOLD]}Initializing security checks...${COLORS[NC]}"

    
    # Run comprehensive security checks
    print_section_header "Basic Vulnerability Scan"
    basic_vulnerability_scan &
    spinner $! "Checking system vulnerabilities"
    echo
      # Update overall progress

    print_section_header "Quick System Enumeration" 
    quick_system_enum &
    spinner $! "Checking for sensitive files and permissions"
    echo

    print_section_header "SUID/SGID Binary Analysis"
    check_suid_sgid &
    spinner $! "Checking for SUID/SGID binaries"
    echo

    print_section_header "User Permissions Audit"
    check_user_permissions &
    spinner $! "Auditing user permissions"
    echo

    print_section_header "File Permissions Analysis"
    check_file_permissions &
    spinner $! "Checking for weak file permissions"
    echo

    print_section_header "Cron Job Inspection"
    check_cron_jobs &
    spinner $! "Inspecting cron jobs"
    echo

    print_section_header "System Integrity Verification"
    check_system_integrity &
    spinner $! "Verifying system integrity"
    echo

    print_section_header "Suspicious Process Check"
    check_suspicious_processes &
    spinner $! "Checking for suspicious processes"
    echo

    print_section_header "Deeper Process Analysis"
    monitor_suspicious_processes &
    spinner $! "performing deeeper analysis"
    echo

    
    check_system_updates &
    spinner $! "Checking for system updates"
    echo

    print_section_header "Open Ports Scan"
    check_open_ports &
    spinner $! "checking for Open ports"
    echo

    print_section_header "Firewall Analysis"
    check_firewall_config &
    spinner $! "Checking firewall configuration"
    echo


    display_vulnerability_summary
}
# Function to compare current results with historical data
    compare_with_historical_data() {

        local previous_report="${CONFIG[REPORT_DIR]}/previous_report.md"
        local current_report="${CONFIG[REPORT_DIR]}/detailed_report.md"

        if [ -f "$previous_report" ]; then
            echo -e "${COLORS[BOLD]}Comparing with previous audit results...${COLORS[NC]}"
            diff -u "$previous_report" "$current_report" > "${CONFIG[REPORT_DIR]}/audit_diff.txt"
            echo -e "${COLORS[GREEN]}${COLORS[BOLD]}[✓] Comparison complete. Diff file generated: ${CONFIG[REPORT_DIR]}/audit_diff.txt${COLORS[NC]}"
        else
            echo -e "${COLORS[YELLOW]}${COLORS[BOLD]}[!] No previous audit data found. Skipping comparison.${COLORS[NC]}"
        fi
}

# Parse command-line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug)
                CONFIG[[Add.info]]=true
                shift
                ;;
            --help)
                print_usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done
}

# Print usage information
print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --debug    Enable debug mode"
    echo "  --help     Display this help message"
}

# Run the script with error handling
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    trap cleanup EXIT
    main "$@"
fi





