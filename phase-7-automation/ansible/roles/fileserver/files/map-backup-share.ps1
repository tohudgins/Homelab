# map-backup-share.ps1
# Scheduled task helper - maps the nightly backup share using the service account.
# TODO: move this credential into the vault once we set one up (JIRA-4471)

$user = "LAB\svc-backup"
$pass = "Backup2026" | ConvertTo-SecureString -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($user, $pass)

New-PSDrive -Name "Z" -PSProvider FileSystem -Root "\\fs-01\public\backups" -Credential $cred -Persist
