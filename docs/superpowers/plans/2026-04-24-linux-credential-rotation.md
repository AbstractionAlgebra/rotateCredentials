# Linux Credential Rotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an Ansible playbook and three roles that rotate root, GRUB, and active LUKS credentials on RHEL 8/9 and Ubuntu 22.04/24.04 using structured vaulted credential records.

**Architecture:** `rotate_credentials.yml` owns orchestration, preflight checks, role enablement, tags, and final summaries. Each role owns one credential domain and appends sanitized status, warning, or failure messages to shared summary lists without printing secret values.

**Tech Stack:** Ansible YAML, built-in Ansible modules, platform commands `getent`, `chage`, `grub2-mkpasswd-pbkdf2`/`grub-mkpasswd-pbkdf2`, `grub2-mkconfig`/`update-grub`, `lsblk`, and `cryptsetup`.

---

## File Structure

- Create `ansible.cfg`: local defaults for role discovery and inventory behavior.
- Create `rotate_credentials.yml`: top-level documented playbook, preflight validation, role calls, and final summary.
- Create `group_vars/all.yml`: non-secret defaults for role booleans and summary lists.
- Create `group_vars/vault.example.yml`: encrypted-vault shape example with non-secret sample values.
- Create `roles/rotate_root_password/tasks/main.yml`: root password rotation and root-only aging enforcement.
- Create `roles/rotate_grub_password/tasks/main.yml`: GRUB2 PBKDF2 hash generation, auth config write, and GRUB config regeneration.
- Create `roles/rotate_luks_password/tasks/main.yml`: active LUKS mapping discovery and passphrase replacement.
- Modify `README.md`: usage, required vaulted variables, tags, subset variables, supported platforms, and test guidance.

## Task 1: Scaffold Repo Defaults And Vault Example

**Files:**
- Create: `ansible.cfg`
- Create: `group_vars/all.yml`
- Create: `group_vars/vault.example.yml`

- [ ] **Step 1: Create `ansible.cfg`**

Write this exact file:

```ini
[defaults]
inventory = inventory
roles_path = roles
host_key_checking = True
retry_files_enabled = False
stdout_callback = default
interpreter_python = auto_silent

[privilege_escalation]
become = True
```

- [ ] **Step 2: Create `group_vars/all.yml`**

Write this exact file:

```yaml
---
rotate_root_password: true
rotate_grub_password: true
rotate_luks_password: true

rotation_successes: []
rotation_warnings: []
rotation_failures: []
rotation_skips: []
```

- [ ] **Step 3: Create `group_vars/vault.example.yml`**

Write this exact file:

```yaml
---
# Copy this structure into an encrypted Ansible Vault file.
# Example values are intentionally non-secret and must be replaced.
root_credential:
  current: "CurrentRootPwd1!"
  new: "NewRootPwdValue1!"
  prior: "PriorRootPwdValue1!"
  current_changed_at: "2026-02-24"
  prior_changed_at: "2025-12-26"

grub_credential:
  current: "CurrentGrubPwd1!"
  new: "NewGrubPwdValue1!"
  prior: "PriorGrubPwdValue1!"
  current_changed_at: "2026-02-24"
  prior_changed_at: "2025-12-26"

luks_credential:
  current: "CurrentLuksPwd1!"
  new: "NewLuksPwdValue1!"
  prior: "PriorLuksPwdValue1!"
  current_changed_at: "2026-02-24"
  prior_changed_at: "2025-12-26"
```

- [ ] **Step 4: Run syntax-neutral file checks**

Run:

```bash
ansible --version
```

Expected: prints installed Ansible version. If Ansible is not installed, record that verification is blocked and continue with file creation tasks.

- [ ] **Step 5: Commit scaffold**

Run:

```bash
git add ansible.cfg group_vars/all.yml group_vars/vault.example.yml
git commit -m "Add Ansible defaults and vault example"
```

Expected: commit succeeds.

## Task 2: Create Documented Playbook With Preflight And Summary

**Files:**
- Create: `rotate_credentials.yml`

- [ ] **Step 1: Create `rotate_credentials.yml` with header documentation and preflight**

Write this exact file:

```yaml
---
# rotate_credentials.yml
#
# Purpose:
#   Rotate Linux root, GRUB, and active LUKS full-disk-encryption credentials.
#
# Supported managed hosts:
#   - RedHat 8
#   - RedHat 9
#   - Ubuntu 22.04
#   - Ubuntu 24.04
#
# Required vaulted records for enabled rotations:
#   root_credential.current
#   root_credential.new
#   root_credential.prior
#   root_credential.current_changed_at
#   root_credential.prior_changed_at
#   grub_credential.current
#   grub_credential.new
#   grub_credential.prior
#   grub_credential.current_changed_at
#   grub_credential.prior_changed_at
#   luks_credential.current
#   luks_credential.new
#   luks_credential.prior
#   luks_credential.current_changed_at
#   luks_credential.prior_changed_at
#
# Enable or disable rotation groups:
#   -e rotate_root_password=true
#   -e rotate_grub_password=true
#   -e rotate_luks_password=true
#
# Tags:
#   --tags root
#   --tags grub
#   --tags luks
#
# Example:
#   ansible-playbook rotate_credentials.yml --ask-vault-pass
#
# Post-run vault maintenance after fully successful hosts:
#   prior = old current
#   prior_changed_at = old current_changed_at
#   current = new
#   current_changed_at = rotation date
#   new = next planned password
#
# Secret handling:
#   Roles must not print current, new, or prior credential values.

- name: Rotate Linux root, GRUB, and LUKS credentials
  hosts: all
  become: true
  gather_facts: true

  vars:
    password_complexity_pattern: '^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[^A-Za-z0-9]).{15,}$'
    supported_os_pairs:
      - os_family: RedHat
        distribution_major_version: "8"
      - os_family: RedHat
        distribution_major_version: "9"
      - os_family: Debian
        distribution: Ubuntu
        distribution_version: "22.04"
      - os_family: Debian
        distribution: Ubuntu
        distribution_version: "24.04"

  pre_tasks:
    - name: Initialize per-host rotation summary lists
      ansible.builtin.set_fact:
        rotation_successes: []
        rotation_warnings: []
        rotation_failures: []
        rotation_skips: []
      tags:
        - always

    - name: Validate supported operating system
      ansible.builtin.assert:
        that:
          - >
            (
              ansible_facts.os_family == 'RedHat' and
              ansible_facts.distribution_major_version in ['8', '9']
            ) or
            (
              ansible_facts.distribution == 'Ubuntu' and
              ansible_facts.distribution_version in ['22.04', '24.04']
            )
        fail_msg: >-
          Unsupported OS {{ ansible_facts.distribution }}
          {{ ansible_facts.distribution_version }} on {{ inventory_hostname }}.
          Supported targets are RHEL 8, RHEL 9, Ubuntu 22.04, and Ubuntu 24.04.
        success_msg: "Supported OS detected on {{ inventory_hostname }}."
      tags:
        - always

    - name: Validate required credential records and complexity
      ansible.builtin.assert:
        that:
          - not rotate_root_password | bool or root_credential is defined
          - not rotate_root_password | bool or root_credential.current is defined
          - not rotate_root_password | bool or root_credential.new is defined
          - not rotate_root_password | bool or root_credential.prior is defined
          - not rotate_root_password | bool or root_credential.current_changed_at is defined
          - not rotate_root_password | bool or root_credential.prior_changed_at is defined
          - not rotate_root_password | bool or root_credential.new is match(password_complexity_pattern)
          - not rotate_grub_password | bool or grub_credential is defined
          - not rotate_grub_password | bool or grub_credential.current is defined
          - not rotate_grub_password | bool or grub_credential.new is defined
          - not rotate_grub_password | bool or grub_credential.prior is defined
          - not rotate_grub_password | bool or grub_credential.current_changed_at is defined
          - not rotate_grub_password | bool or grub_credential.prior_changed_at is defined
          - not rotate_grub_password | bool or grub_credential.new is match(password_complexity_pattern)
          - not rotate_luks_password | bool or luks_credential is defined
          - not rotate_luks_password | bool or luks_credential.current is defined
          - not rotate_luks_password | bool or luks_credential.new is defined
          - not rotate_luks_password | bool or luks_credential.prior is defined
          - not rotate_luks_password | bool or luks_credential.current_changed_at is defined
          - not rotate_luks_password | bool or luks_credential.prior_changed_at is defined
          - not rotate_luks_password | bool or luks_credential.new is match(password_complexity_pattern)
        fail_msg: >-
          Missing required vaulted credential fields or weak new password.
          Enabled new passwords must be at least 15 characters and include
          uppercase, lowercase, number, and symbol characters.
      no_log: true
      tags:
        - always

    - name: Validate required commands are present
      ansible.builtin.shell: "command -v {{ item }}"
      changed_when: false
      loop: "{{ required_rotation_commands }}"
      vars:
        required_rotation_commands: >-
          {{
            ['getent', 'chage'] +
            (['grub2-mkpasswd-pbkdf2', 'grub2-mkconfig'] if rotate_grub_password | bool and ansible_facts.os_family == 'RedHat' else []) +
            (['grub-mkpasswd-pbkdf2', 'update-grub'] if rotate_grub_password | bool and ansible_facts.distribution == 'Ubuntu' else []) +
            (['lsblk', 'cryptsetup'] if rotate_luks_password | bool else [])
          }}
      tags:
        - always

  roles:
    - role: rotate_root_password
      when: rotate_root_password | bool
      tags:
        - root

    - role: rotate_grub_password
      when: rotate_grub_password | bool
      tags:
        - grub

    - role: rotate_luks_password
      when: rotate_luks_password | bool
      tags:
        - luks

  post_tasks:
    - name: Record skipped root rotation
      ansible.builtin.set_fact:
        rotation_skips: "{{ rotation_skips + ['root rotation skipped by rotate_root_password=false'] }}"
      when: not rotate_root_password | bool
      tags:
        - always

    - name: Record skipped GRUB rotation
      ansible.builtin.set_fact:
        rotation_skips: "{{ rotation_skips + ['GRUB rotation skipped by rotate_grub_password=false'] }}"
      when: not rotate_grub_password | bool
      tags:
        - always

    - name: Record skipped LUKS rotation
      ansible.builtin.set_fact:
        rotation_skips: "{{ rotation_skips + ['LUKS rotation skipped by rotate_luks_password=false'] }}"
      when: not rotate_luks_password | bool
      tags:
        - always

    - name: Print sanitized rotation summary
      ansible.builtin.debug:
        msg:
          host: "{{ inventory_hostname }}"
          successes: "{{ rotation_successes }}"
          warnings: "{{ rotation_warnings }}"
          failures: "{{ rotation_failures }}"
          skips: "{{ rotation_skips }}"
          vault_update_required_after_full_success: >-
            If every enabled rotation succeeded for this host, update the
            encrypted vault record: prior = old current, prior_changed_at =
            old current_changed_at, current = new, current_changed_at =
            {{ ansible_date_time.date }}, and new = next planned password.
      tags:
        - always

    - name: Fail host when any rotation failure was recorded
      ansible.builtin.fail:
        msg: "Credential rotation failures require investigation: {{ rotation_failures }}"
      when: rotation_failures | length > 0
      tags:
        - always
```

- [ ] **Step 2: Run syntax check**

Run:

```bash
ansible-playbook rotate_credentials.yml --syntax-check
```

Expected: fails only because inventory or vaulted variables are not yet provided, or passes if Ansible accepts syntax without inventory. There must be no YAML parser errors.

- [ ] **Step 3: Commit playbook**

Run:

```bash
git add rotate_credentials.yml
git commit -m "Add credential rotation playbook"
```

Expected: commit succeeds.

## Task 3: Implement Root Password Role

**Files:**
- Create: `roles/rotate_root_password/tasks/main.yml`

- [ ] **Step 1: Create root role tasks**

Write this exact file:

```yaml
---
- name: Read current root shadow aging data
  ansible.builtin.command: getent shadow root
  register: root_shadow_before
  changed_when: false

- name: Calculate current root max-days value
  ansible.builtin.set_fact:
    root_max_days_before: "{{ (root_shadow_before.stdout.split(':')[4] | default('')) | string }}"

- name: Rotate root password and aging settings
  block:
    - name: Set root password
      ansible.builtin.user:
        name: root
        password: "{{ root_credential.new | password_hash('sha512') }}"
        update_password: always
      no_log: true

    - name: Set root password last-change date to today
      ansible.builtin.command: "chage -d {{ ansible_date_time.date }} root"
      changed_when: true

    - name: Ensure root max-days aging is 60
      ansible.builtin.command: chage -M 60 root
      changed_when: root_max_days_before != '60'

    - name: Record root max-days warning when corrected
      ansible.builtin.set_fact:
        rotation_warnings: "{{ rotation_warnings + ['root max-days was ' ~ root_max_days_before ~ ' and was corrected to 60'] }}"
      when: root_max_days_before != '60'

    - name: Record root password rotation success
      ansible.builtin.set_fact:
        rotation_successes: "{{ rotation_successes + ['root password rotated and root max-days enforced'] }}"

  rescue:
    - name: Record root password rotation failure
      ansible.builtin.set_fact:
        rotation_failures: "{{ rotation_failures + ['root password rotation failed; inspect task output for the failed root account or chage operation'] }}"
```

- [ ] **Step 2: Run syntax check**

Run:

```bash
ansible-playbook rotate_credentials.yml --syntax-check
```

Expected: no YAML parser errors.

- [ ] **Step 3: Commit root role**

Run:

```bash
git add roles/rotate_root_password/tasks/main.yml
git commit -m "Add root password rotation role"
```

Expected: commit succeeds.

## Task 4: Implement GRUB Password Role

**Files:**
- Create: `roles/rotate_grub_password/tasks/main.yml`

- [ ] **Step 1: Create GRUB role tasks**

Write this exact file:

```yaml
---
- name: Set GRUB platform facts
  ansible.builtin.set_fact:
    grub_mkpasswd_command: "{{ 'grub2-mkpasswd-pbkdf2' if ansible_facts.os_family == 'RedHat' else 'grub-mkpasswd-pbkdf2' }}"
    grub_auth_file: "{{ '/etc/grub.d/01_users' if ansible_facts.os_family == 'RedHat' else '/etc/grub.d/40_custom' }}"
    grub_mkconfig_command: "{{ 'grub2-mkconfig -o /boot/grub2/grub.cfg' if ansible_facts.os_family == 'RedHat' else 'update-grub' }}"

- name: Validate GRUB password hash command is present
  ansible.builtin.shell: "command -v {{ grub_mkpasswd_command }}"
  changed_when: false

- name: Rotate GRUB password
  block:
    - name: Generate GRUB PBKDF2 hash
      ansible.builtin.command: "{{ grub_mkpasswd_command }}"
      register: grub_password_hash
      changed_when: false
      no_log: true
      args:
        stdin: "{{ grub_credential.new }}\n{{ grub_credential.new }}\n"

    - name: Validate generated GRUB hash format
      ansible.builtin.assert:
        that:
          - grub_password_hash.stdout is search('grub\\.pbkdf2\\.sha512\\.')
        fail_msg: "GRUB PBKDF2 hash generation failed on {{ inventory_hostname }}."
      no_log: true

    - name: Extract generated GRUB hash
      ansible.builtin.set_fact:
        grub_password_hash_value: "{{ grub_password_hash.stdout | regex_search('grub\\.pbkdf2\\.sha512\\.[^\\s]+') }}"
      no_log: true

    - name: Write GRUB authentication configuration
      ansible.builtin.blockinfile:
        path: "{{ grub_auth_file }}"
        create: true
        mode: "0755"
        owner: root
        group: root
        marker: "# {mark} ANSIBLE MANAGED GRUB PASSWORD"
        block: |
          set superusers="root"
          password_pbkdf2 root {{ grub_password_hash_value }}
      no_log: true

    - name: Regenerate GRUB configuration
      ansible.builtin.command: "{{ grub_mkconfig_command }}"
      changed_when: true

    - name: Record GRUB password rotation success
      ansible.builtin.set_fact:
        rotation_successes: "{{ rotation_successes + ['GRUB password rotated using standard GRUB2 PBKDF2 authentication'] }}"

  rescue:
    - name: Record GRUB password rotation failure
      ansible.builtin.set_fact:
        rotation_failures: "{{ rotation_failures + ['GRUB password rotation failed; verify GRUB password tooling, auth file path, and GRUB config regeneration on this host'] }}"
```

- [ ] **Step 2: Run syntax check**

Run:

```bash
ansible-playbook rotate_credentials.yml --syntax-check
```

Expected: no YAML parser errors.

- [ ] **Step 3: Commit GRUB role**

Run:

```bash
git add roles/rotate_grub_password/tasks/main.yml
git commit -m "Add GRUB password rotation role"
```

Expected: commit succeeds.

## Task 5: Implement LUKS Password Role

**Files:**
- Create: `roles/rotate_luks_password/tasks/main.yml`
- Create: `roles/rotate_luks_password/tasks/rotate_one.yml`

- [ ] **Step 1: Create LUKS role tasks**

Write this exact file:

```yaml
---
- name: Discover active LUKS mappings and backing devices
  ansible.builtin.shell: |
    set -o pipefail
    lsblk -rpno NAME,TYPE,PKNAME | awk '$2 == "crypt" && $3 != "" { print $1 "|" $3 }'
  args:
    executable: /bin/bash
  register: luks_discovery
  changed_when: false

- name: Build active LUKS device records
  ansible.builtin.set_fact:
    luks_devices: "{{ luks_devices | default([]) + [{'mapping': item.split('|')[0], 'device': item.split('|')[1]}] }}"
  loop: "{{ luks_discovery.stdout_lines }}"
  when: item | length > 0

- name: Record no active LUKS devices skip
  ansible.builtin.set_fact:
    rotation_skips: "{{ rotation_skips + ['LUKS rotation skipped because no active LUKS mappings were discovered'] }}"
  when: (luks_devices | default([])) | length == 0

- name: Rotate discovered LUKS device passphrases
  ansible.builtin.include_tasks: rotate_one.yml
  loop: "{{ luks_devices | default([]) }}"
  loop_control:
    loop_var: luks_device
    label: "{{ luks_device.mapping }} -> {{ luks_device.device }}"
```

- [ ] **Step 2: Create per-device LUKS task file**

Create `roles/rotate_luks_password/tasks/rotate_one.yml` with this exact file:

```yaml
---
- name: Rotate LUKS passphrase for {{ luks_device.mapping }}
  block:
    - name: Add new LUKS passphrase for {{ luks_device.device }}
      ansible.builtin.command: "cryptsetup luksAddKey {{ luks_device.device }}"
      args:
        stdin: "{{ luks_credential.current }}\n{{ luks_credential.new }}\n{{ luks_credential.new }}\n"
      changed_when: true
      no_log: true

    - name: Verify new LUKS passphrase for {{ luks_device.device }}
      ansible.builtin.command: "cryptsetup open --test-passphrase {{ luks_device.device }}"
      args:
        stdin: "{{ luks_credential.new }}\n"
      changed_when: false
      no_log: true

    - name: Remove old LUKS passphrase for {{ luks_device.device }}
      ansible.builtin.command: "cryptsetup luksRemoveKey {{ luks_device.device }}"
      args:
        stdin: "{{ luks_credential.current }}\n"
      changed_when: true
      no_log: true

    - name: Record LUKS rotation success for {{ luks_device.mapping }}
      ansible.builtin.set_fact:
        rotation_successes: "{{ rotation_successes + ['LUKS passphrase rotated for mapping ' ~ luks_device.mapping ~ ' backing device ' ~ luks_device.device] }}"

  rescue:
    - name: Record LUKS rotation failure for {{ luks_device.mapping }}
      ansible.builtin.set_fact:
        rotation_failures: "{{ rotation_failures + ['LUKS passphrase rotation failed for mapping ' ~ luks_device.mapping ~ ' backing device ' ~ luks_device.device ~ '; verify current/new passphrases, available keyslots, and cryptsetup output'] }}"
```

- [ ] **Step 3: Run syntax check**

Run:

```bash
ansible-playbook rotate_credentials.yml --syntax-check
```

Expected: no YAML parser errors.

- [ ] **Step 4: Commit LUKS role**

Run:

```bash
git add roles/rotate_luks_password/tasks/main.yml roles/rotate_luks_password/tasks/rotate_one.yml
git commit -m "Add LUKS passphrase rotation role"
```

Expected: commit succeeds.

## Task 6: Add Operator Documentation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace `README.md`**

Write this exact file:

```markdown
# rotateCredentials

Ansible playbook and roles for rotating Linux root, GRUB, and active LUKS full-disk-encryption credentials.

## Supported Hosts

- RHEL 8
- RHEL 9
- Ubuntu 22.04
- Ubuntu 24.04

The roles are designed for hardened systems that commonly use FIPS kernels and STIG security settings. They do not install missing packages.

## Credentials

Store credentials in Ansible Vault using the shape shown in `group_vars/vault.example.yml`.

Each enabled credential record requires:

- `current`
- `new`
- `prior`
- `current_changed_at`
- `prior_changed_at`

Each enabled `new` value must be at least 15 characters and include uppercase, lowercase, number, and symbol characters.

Secret values are not printed in normal play output.

## Run

```bash
ansible-playbook rotate_credentials.yml --ask-vault-pass
```

## Run A Subset

Use boolean variables:

```bash
ansible-playbook rotate_credentials.yml --ask-vault-pass -e rotate_luks_password=false
```

Use tags:

```bash
ansible-playbook rotate_credentials.yml --ask-vault-pass --tags root
ansible-playbook rotate_credentials.yml --ask-vault-pass --tags grub
ansible-playbook rotate_credentials.yml --ask-vault-pass --tags luks
```

## Post-Run Vault Update

After a host fully succeeds, update the encrypted vault manually:

```text
prior = old current
prior_changed_at = old current_changed_at
current = new
current_changed_at = rotation date
new = next planned password
```

Keep failed hosts under investigation before promoting values for those systems.

## Verification

Run syntax checks before using the playbook:

```bash
ansible-playbook rotate_credentials.yml --syntax-check
```

Run destructive GRUB and LUKS validation only in disposable RHEL 8, RHEL 9, Ubuntu 22.04, and Ubuntu 24.04 VMs with snapshots and encrypted disks.
```

- [ ] **Step 2: Run syntax check**

Run:

```bash
ansible-playbook rotate_credentials.yml --syntax-check
```

Expected: no YAML parser errors.

- [ ] **Step 3: Commit documentation**

Run:

```bash
git add README.md
git commit -m "Document credential rotation playbook usage"
```

Expected: commit succeeds.

## Task 7: Final Verification

**Files:**
- Verify: all created Ansible and documentation files

- [ ] **Step 1: Check for accidental secret output patterns**

Run:

```bash
rg -n "debug:|msg:.*credential\\.(current|new|prior)|stdout:.*credential|no_log: false" rotate_credentials.yml roles group_vars README.md
```

Expected: no lines that print credential values. The sanitized final summary in `rotate_credentials.yml` may appear because it prints status lists, not credential values.

- [ ] **Step 2: Run Ansible syntax check**

Run:

```bash
ansible-playbook rotate_credentials.yml --syntax-check
```

Expected: no YAML parser errors.

- [ ] **Step 3: Run lint if available**

Run:

```bash
ansible-lint
```

Expected: pass, or report that `ansible-lint` is not installed. Fix actionable lint failures that do not add complexity or change approved scope.

- [ ] **Step 4: Inspect git status**

Run:

```bash
git status --short
```

Expected: clean worktree after the previous task commits, or only intentional uncommitted verification notes if a tool generated local output.

- [ ] **Step 5: Record final implementation verification**

If the syntax check passed and lint either passed or was unavailable, report:

```text
Implemented Linux credential rotation playbook and roles.
Verified with ansible-playbook --syntax-check.
ansible-lint: passed or unavailable.
Destructive GRUB and LUKS behavior still requires disposable VM validation.
```

If syntax check failed, fix the exact YAML or Ansible error before reporting completion.
