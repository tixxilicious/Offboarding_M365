# offboard-exo-interactive.ps1
# Interaktives Offboarding (Exchange-lastig) – läuft in Windows PowerShell 5.1 und PowerShell 7
# Voraussetzungen: Install-Module ExchangeOnlineManagement
# Optional für Entra (Block/Revoke): Install-Module Microsoft.Graph -Scope AllUsers

$ErrorActionPreference = "Stop"

function Info($m){ Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m){ Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }

function Ask($prompt, $default = $null) {
  if ($null -ne $default -and $default -ne "") {
    $a = Read-Host "$prompt [$default]"
    if ([string]::IsNullOrWhiteSpace($a)) { return $default }
    return $a
  } else {
    return (Read-Host $prompt)
  }
}

function AskYesNo($prompt, $defaultYes = $false) {
  if ($defaultYes) { $suffix = "Y/n" } else { $suffix = "y/N" }
  $a = Read-Host "$prompt ($suffix)"
  if ([string]::IsNullOrWhiteSpace($a)) { return $defaultYes }

  switch ($a.Trim().ToLower()) {
    "y"   { return $true }
    "yes" { return $true }
    "j"   { return $true }
    "ja"  { return $true }
    default { return $false }
  }
}

Info "=== Exchange Online Offboarding (interaktiv) ==="

# --- Connect EXO ---
Info "Connecting to Exchange Online..."
Import-Module ExchangeOnlineManagement -ErrorAction Stop
Connect-ExchangeOnline -ShowBanner:$false

try {
  # --- Eingaben (Enter = überspringen/Default) ---
  $User = Ask "UPN / Mailadresse des Mitarbeiters (z.B. max@firma.de)"
  if ([string]::IsNullOrWhiteSpace($User)) { throw "Kein User angegeben." }

  $ForwardTo = Ask "Optional: Weiterleitung an (leer = keine/entfernen)" ""
  $DoForward = -not [string]::IsNullOrWhiteSpace($ForwardTo)

  $DoOOF   = AskYesNo "Abwesenheitsnotiz (OOF) setzen?" $false
  $OOFText = ""
  if ($DoOOF) {
    $OOFText = Ask "OOF Text (leer = Standardtext)" ""
  }

  $ConvertToShared = AskYesNo "Mailbox in Shared Mailbox umwandeln?" $true
  $HideFromGAL     = AskYesNo "Aus Adresslisten ausblenden (Hide from GAL)?" $true

  $DoBlockSignIn   = AskYesNo "Login sperren (Entra accountEnabled=false)?" $true
  $DoRevokeTokens  = AskYesNo "Sessions/Tokens revoken (Entra)?" $true

  Info "Resolving mailbox: $User"
  $mbx = Get-EXOMailbox -Identity $User -ErrorAction Stop
  $upn = $mbx.UserPrincipalName
  Ok "Found: $($mbx.DisplayName) <$upn>"

  # --- 1) Aus Distribution Groups entfernen (classic DG) ---
  Info "Removing from Distribution Groups (classic)..."
  $removed = 0
  $dgs = Get-DistributionGroup -ResultSize Unlimited
  foreach($dg in $dgs){
    try{
      $members = Get-DistributionGroupMember -Identity $dg.Identity -ResultSize Unlimited -ErrorAction Stop
      if($members.PrimarySmtpAddress -contains $upn){
        Remove-DistributionGroupMember -Identity $dg.Identity -Member $upn -Confirm:$false -BypassSecurityGroupManagerCheck
        $removed++
        Ok "Removed from DG: $($dg.DisplayName)"
      }
    } catch { }
  }
  Info "DG removed count: $removed"
  Warn "Dynamic Distribution Groups sind regelbasiert -> kein 'Entfernen' möglich."

  # --- 2) Berechtigungen entfernen: User hat Zugriff auf ANDERE Mailboxen ---
  Info "Removing permissions where USER has access on OTHER mailboxes (FullAccess/SendAs/SendOnBehalf)..."
  $allMbx = Get-EXOMailbox -ResultSize Unlimited -Properties UserPrincipalName

  foreach($m in $allMbx){
    $id = $m.UserPrincipalName

    # FullAccess
    try{
      $perms = Get-EXOMailboxPermission -Identity $id -ErrorAction Stop |
        Where-Object { $_.User -like "*$upn*" -and $_.AccessRights -contains "FullAccess" -and -not $_.IsInherited }
      foreach($p in $perms){
        Remove-MailboxPermission -Identity $id -User $upn -AccessRights FullAccess -InheritanceType All -Confirm:$false
        Ok "Removed FullAccess: $upn from $id"
      }
    } catch {}

    # SendAs
    try{
      $ras = Get-RecipientPermission -Identity $id -ErrorAction Stop |
        Where-Object { $_.Trustee -eq $upn -and $_.AccessRights -contains "SendAs" }
      foreach($ra in $ras){
        Remove-RecipientPermission -Identity $id -Trustee $upn -AccessRights SendAs -Confirm:$false
        Ok "Removed SendAs: $upn on $id"
      }
    } catch {}

    # SendOnBehalf
    try{
      $grant = (Get-EXOMailbox -Identity $id -Properties GrantSendOnBehalfTo).GrantSendOnBehalfTo
      if($grant){
        $new = $grant | Where-Object { $_.PrimarySmtpAddress -ne $upn }
        if($new.Count -ne $grant.Count){
          Set-Mailbox -Identity $id -GrantSendOnBehalfTo $new
          Ok "Removed SendOnBehalf: $upn from $id"
        }
      }
    } catch {}
  }

  # --- 3) Berechtigungen entfernen: ANDERE haben Zugriff auf die Offboard-Mailbox ---
  Info "Removing delegates on OFFBOARDED mailbox (FullAccess/SendAs/SendOnBehalf)..."

  # FullAccess delegates
  try{
    $mbxPerms = Get-EXOMailboxPermission -Identity $upn -ErrorAction Stop |
      Where-Object { $_.AccessRights -contains "FullAccess" -and -not $_.IsInherited -and $_.User -notlike "NT AUTHORITY\SELF" }
    foreach($p in $mbxPerms){
      Remove-MailboxPermission -Identity $upn -User $p.User -AccessRights FullAccess -InheritanceType All -Confirm:$false
      Ok "Removed delegate FullAccess: $($p.User)"
    }
  } catch {}

  # SendAs delegates
  try{
    $recPerms = Get-RecipientPermission -Identity $upn -ErrorAction Stop |
      Where-Object { $_.AccessRights -contains "SendAs" }
    foreach($p in $recPerms){
      Remove-RecipientPermission -Identity $upn -Trustee $p.Trustee -AccessRights SendAs -Confirm:$false
      Ok "Removed delegate SendAs: $($p.Trustee)"
    }
  } catch {}

  # SendOnBehalf delegates
  try{
    $grant = (Get-EXOMailbox -Identity $upn -Properties GrantSendOnBehalfTo).GrantSendOnBehalfTo
    if($grant){
      Set-Mailbox -Identity $upn -GrantSendOnBehalfTo @()
      Ok "Cleared GrantSendOnBehalfTo on $upn"
    }
  } catch {}

  # --- 4) Forwarding ---
  if($DoForward){
    Info "Setting forwarding to: $ForwardTo (deliver to mailbox + forward)"
    Set-Mailbox -Identity $upn -DeliverToMailboxAndForward $true -ForwardingSmtpAddress $ForwardTo
    Ok "Forwarding configured."
  } else {
    Info "Clearing forwarding (if set)"
    Set-Mailbox -Identity $upn -ForwardingAddress $null -ForwardingSmtpAddress $null -DeliverToMailboxAndForward $false
    Ok "Forwarding cleared."
  }

  # --- 5) OOF ---
  if($DoOOF){
    if ([string]::IsNullOrWhiteSpace($OOFText)) {
      $OOFText = "Vielen Dank für Ihre Nachricht. Diese Mailbox wird nicht mehr aktiv betreut."
    }
    Info "Setting OOF"
    Set-MailboxAutoReplyConfiguration -Identity $upn -AutoReplyState Enabled -InternalMessage $OOFText -ExternalMessage $OOFText
    Ok "OOF enabled."
  } else {
    Info "Disabling OOF (if enabled)"
    Set-MailboxAutoReplyConfiguration -Identity $upn -AutoReplyState Disabled
  }

  # --- 6) Hide from GAL ---
  if($HideFromGAL){
    Info "Hiding from GAL"
    Set-Mailbox -Identity $upn -HiddenFromAddressListsEnabled $true
    Ok "HiddenFromAddressListsEnabled = true"
  } else {
    Info "Unhiding from GAL"
    Set-Mailbox -Identity $upn -HiddenFromAddressListsEnabled $false
  }

  # --- 7) Convert to Shared ---
  if($ConvertToShared){
    Info "Converting to Shared Mailbox"
    Set-Mailbox -Identity $upn -Type Shared
    Ok "Converted to Shared."
  } else {
    Info "Leaving mailbox type unchanged."
  }

  # --- 8) Optional: Entra actions (best effort) ---
  if($DoBlockSignIn -or $DoRevokeTokens){
    if (Get-Module -ListAvailable -Name Microsoft.Graph.Users) {
      Info "Graph PowerShell SDK gefunden -> Entra Aktionen möglich."
      Import-Module Microsoft.Graph.Users -ErrorAction Stop

      # kann interaktiv nach Login/Consent fragen
      Connect-MgGraph -Scopes "User.ReadWrite.All" | Out-Null
      $u = Get-MgUser -UserId $upn -ErrorAction Stop

      if($DoBlockSignIn){
        Info "Disabling account (accountEnabled=false)"
        Update-MgUser -UserId $u.Id -AccountEnabled:$false
        Ok "Account disabled."
      }
      if($DoRevokeTokens){
        Info "Revoking sign-in sessions"
        Revoke-MgUserSignInSession -UserId $u.Id | Out-Null
        Ok "Sessions revoked."
      }

      Disconnect-MgGraph | Out-Null
    } else {
      Warn "Microsoft.Graph.Users nicht installiert -> Entra Aktionen übersprungen."
      Warn "Install: Install-Module Microsoft.Graph -Scope AllUsers"
    }
  }

  Info "=== Fertig ==="
}
finally {
  Disconnect-ExchangeOnline -Confirm:$false | Out-Null
  Info "Disconnected."
}
