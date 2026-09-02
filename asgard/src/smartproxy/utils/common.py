HACKING_COMMANDS = ["nmap",
                "nc",
                "ssh",
                "volatility", 
                "wireshark", 
                "sqlmap", 
                "ping", 
                "nslookup", 
                "traceroute", 
                "traceroute6", 
                "tracepath",
                "tracepath6",
                "arp",
                "ip",
                "ifconfig",
                "netstat",
                "ss",
                "telnet",
                "mount",
                "sftp-server"]

DOWNLOAD_COMMANDS = [
                "wget",
                "curl",
                "ftp",
                "fetch",
                "tftp",
                "sftp",
                "ftpget",
                "ftpput",
                "lwp-download",
                "dget"
]

EXEC_PATTERNS = [
            "exec_custom_cmd",
            "exec_echo_base64_shell",
            "exec_echo_shell",
            "exec_perl",
            "exec_shell_script",
            "exec_nohup",
            "exec_busybox",
            "exec_exit",
            "exec_user_chpasswd",
            "exec_root_chpasswd",
            "exec_hacking_cmd",
            "exec_download_cmd"
            ]

BUILD = ["make", "gcc", "cc", "ld", "as", "cc1", "ldd"]
ENVVAR = ["export", "set", "unset", "which", "history"]
USER = ["w", "users", "finger", "who", "id", "last", "groups", "whoami"]
FILESYS = ["cd", "ls", "cp", "dir", "pwd", "more",
            "dirname", "basename", "find", "locate", "findfs", "cat", "tee"]
PASSWORD = ["passwd", "chpasswd"]
PRIVILEDGE = ["sudo", "su"]
UTILITIES = ["grep", "sed", "tr", "awk", "sort", "uniq", "wc", "head"]
DECODER = ["base64"]
PROCESS = ["kill", "killall", "ps", "top", "sleep", "nohup", "pkill"]
INSTALL = ["tar", "gzip", "unzip", "cp", "chmod", "mkdir", "mv", "apt", "apt-get"]
SHELL = ["bash", "sh", "csh"]
SCRIPT = ["perl", "python", "run-parts"]
DOC = ["man", "help"]
COMM = ["write", "wall"]
CLEAR_CONSOLE = ["clear", "clear_console"]
HARDWARE = ["nproc", "uname", "uptime", "free",  "df", "lscpu", "lsb_release", "hostname"]

ChangeFS = ["nano", "vim", "touch", "pico", "vi", "emacs", "rm", "ln"]

"""
Paper: Profiling Attacker Behavior Following SSH Compromises
Author: Daniel Ramsbrock
"""

Ramsbrock_exec_CheckSW = [
    "w", "id", "whoami", "last", "ps", 
    "cat /etc/*", "history", "cat .bash_history", "php -v",
    "top", "sshd -V", "show", "modelname", "users", "crontab",
    "hostname", "who", "info", "help"] # + show, +modelname for asguard, +users, +who
Ramsbrock_exec_Install = [
    "tar", "unzip", "mv", "rm", "cp", "chmod",
    "mkdir", "dos2unix", "apt", "apt-get", "yum",
    "scp", "rpm", "touch", "make"]
# Ramsbrock_exec_Download = ["wget", "ftp", "curl", "lwp-download"]
Ramsbrock_exec_Download = [
    "wget", "ftp", "curl", "lwp-download", "fetch", "tftp",
    "sftp", "ftpget", "ftpput", "dget"]
Ramsbrock_exec_Run = [
    "./", "perl", "python", "cround", "[kjournald]",
    "httpd", "*.pl", "sh", "python3", "nohup", "nc",
    "nice", "disown"] # base64 --decode | bash
Ramsbrock_exec_Password = ["passwd", "chpasswd", "hive-passwd"] # + chpasswd

"""
we compare the following command:

if command -v nvidia-smi ; then echo "Yes" ; else echo "No" ; fi'

to check for 'nvidia-smi', as there might be a problem of parsing.
"""
Ramsbrock_exec_CheckHW = [
    "uptime", "ifconfig", "uname", "cat /proc/cpuinfo",
    "nvidia-smi", "nvidia-info", "amd-info", "pci", "free",
    "lscpu", "lspci", "nproc",
    'if command -v nvidia-smi ; then echo "Yes" ; else echo "No" ; fi',
    "ip", "dmesg", "dmidecode"] 

Ramsbrock_exec_ChangeConf = [
    "export", "PATH=", "kill", "nano",
    "pico", "vi", "vim", "sshd", "useradd", "userdel",
    "pkill", "systemctl", "killall", "service", "unset",
    "set", "usermod", "halt", "shellinabox"] # systemctl, killall, service

Rambsbrock_exec_NoOP = [
    "cd", "grep", "sleep", "cat",
    "ls", "dir", "exit", "echo", "egrep", "cut", "awk",
     "uniq", "screen","clear", "head", "bash", "sed",
    "wc", "tr", "which"]

Ramsbrock_EXEC_PATTERNS = [
    "Ramsbrock_exec_CheckSW",
    "Ramsbrock_exec_Install",
    "Ramsbrock_exec_Download",
    "Ramsbrock_exec_Run",
    "Ramsbrock_exec_Password",
    "Ramsbrock_exec_CheckHW",
    "Ramsbrock_exec_ChangeConf"
]

Ramsbrock_COUNT_PATTERNS = [
    "Ramsbrock_count_CheckSW",
    "Ramsbrock_count_Install",
    "Ramsbrock_count_Download",
    "Ramsbrock_count_Run",
    "Ramsbrock_count_Password",
    "Ramsbrock_count_CheckHW",
    "Ramsbrock_count_ChangeConf"
]

EDITOR = ["nano", "vim", "pico", "vi", "emacs", "edit"]
INTERACTIVE = ["top", "ping", "rm", "passwd", "apt", "apt-get",
               "python", "python2", "python2.7", "python3", "info"]
SHELL = ["bash", "sh", "csh"]

EXEC_PATTERNS_COUNT = []

for p in EXEC_PATTERNS:
    EXEC_PATTERNS_COUNT.append(p + "_count")

for p in DOWNLOAD_COMMANDS:
    EXEC_PATTERNS_COUNT.append(p + "_count")

for p in HACKING_COMMANDS:
    EXEC_PATTERNS_COUNT.append(p + "_count")

ALL_ = HACKING_COMMANDS + DOWNLOAD_COMMANDS + EXEC_PATTERNS