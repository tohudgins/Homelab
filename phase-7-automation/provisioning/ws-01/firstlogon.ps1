# ws-01 first-logon provisioning - runs once, from autounattend.xml FirstLogonCommands
# (as localadmin, via AutoLogon). Takes a bare Windows install to "reachable over SSH":
#   1. install VMware Tools from the drivers CD  -> brings the vmxnet3 NIC driver
#   2. give the NIC ws-01's static CORP address  (CORP has no DHCP - see docs/00-ip-plan.md)
#   3. install Win32-OpenSSH from the answer CD  (no internet needed) and start sshd
#   4. authorize the homelab key for the `windows` Ansible role
#
# Progress goes to C:\firstlogon.log AND the VM's serial port (COM1). The serial line
# is the only window into a headless guest before networking exists: on the Mac it is
# ~/Virtual Machines.localized/<vm>.vmwarevm/<vm>-serial.log.
$ErrorActionPreference = 'Stop'

$Address = '10.10.10.50'
$Prefix  = 24
$Gateway = '10.10.10.1'
$Dns     = '10.10.10.10'
$PubKey  = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH7GQV6ykcpEB9lPX4PtS48LOUIeL2N/gA4w5biGD+XS tohudgins@mac-homelab-jumphost'

$com = $null
try { $com = New-Object System.IO.Ports.SerialPort 'COM1', 115200; $com.Open() } catch { $com = $null }
function Log([string]$msg) {
    $line = '{0} [firstlogon] {1}' -f (Get-Date -Format 'HH:mm:ss'), $msg
    Add-Content -Path C:\firstlogon.log -Value $line
    if ($com) { try { $com.WriteLine($line) } catch { } }
}

function Find-Volume([string]$label) {
    $v = Get-Volume | Where-Object { $_.FileSystemLabel -eq $label -and $_.DriveLetter } | Select-Object -First 1
    if (-not $v) { throw "no volume labelled '$label' - is the CD attached?" }
    return "$($v.DriveLetter):\"
}

try {
    Log 'start'

    # 1. VMware Tools (drivers). REBOOT=R: never reboot mid-provisioning.
    $tools = Find-Volume 'VMware Tools'
    Log "installing VMware Tools from $tools"
    $p = Start-Process -FilePath "$($tools)setup.exe" -ArgumentList '/S', '/v"/qn REBOOT=R ADDLOCAL=ALL"' -Wait -PassThru
    Log "VMware Tools setup exit code $($p.ExitCode)"

    # 2. Wait for the vmxnet3 adapter, then address it.
    $nic = $null
    for ($i = 0; $i -lt 60 -and -not $nic; $i++) {
        $nic = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | Select-Object -First 1
        if (-not $nic) { Start-Sleep -Seconds 2 }
    }
    if (-not $nic) { throw 'no network adapter came up after VMware Tools install' }
    Log "adapter '$($nic.Name)' ($($nic.InterfaceDescription)) is up"
    Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -ne $Address } | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    if (-not (Get-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $Address -ErrorAction SilentlyContinue)) {
        New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $Address -PrefixLength $Prefix -DefaultGateway $Gateway | Out-Null
    }
    Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $Dns
    Get-NetConnectionProfile -InterfaceIndex $nic.ifIndex -ErrorAction SilentlyContinue |
        Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue
    Log "static address $Address/$Prefix gw $Gateway dns $Dns set"

    # 3. OpenSSH from the answer CD.
    $answer = Find-Volume 'WSANSWER'
    Log "installing OpenSSH from $answer"
    $p = Start-Process msiexec.exe -ArgumentList '/i', "`"$($answer)openssh-arm64.msi`"", '/qn', '/norestart' -Wait -PassThru
    Log "OpenSSH msi exit code $($p.ExitCode)"
    if ($p.ExitCode -notin 0, 3010) { throw "OpenSSH MSI failed ($($p.ExitCode))" }
    Set-Service sshd -StartupType Automatic
    Start-Service sshd
    if (-not (Get-NetFirewallRule -Name 'sshd-in' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name 'sshd-in' -DisplayName 'OpenSSH Server (22)' -Enabled True `
            -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
    }
    Log 'sshd running'

    # 4. Authorize the homelab key for Administrators (sshd_config's `Match Group
    #    administrators` reads this file, not the per-user one).
    $ak = 'C:\ProgramData\ssh\administrators_authorized_keys'
    New-Item -ItemType Directory -Force -Path (Split-Path $ak) | Out-Null
    Set-Content -Path $ak -Value $PubKey -Encoding ascii
    icacls $ak /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
    Log 'authorized key installed - DONE'
}
catch {
    Log "FAILED: $($_.Exception.Message)"
    Log ($_.ScriptStackTrace -replace "`r?`n", ' | ')
    exit 1
}
