# Linux Credential Rotation Design

Date: 2026-04-24

## Purpose

Create a simple Ansible project that rotates Linux root, GRUB, and LUKS full-disk-encryption credentials on supported hardened systems. The target platforms are RHEL 8, RHEL 9, Ubuntu 22.04, and Ubuntu 24.04, including systems commonly running FIPS kernels and STIG security settings.

The project will provide one top-level playbook that calls three focused roles. Operators will provide credential data through Ansible Vault. The playbook will validate new credential complexity, perform enabled rotations, report failures clearly, and print post-run vault update instructions.

## Repository Shape

The implementation will use a conventional Ansible layout:

```text
rotate_credentials.yml
roles/
  rotate_root_password/
  rotate_grub_password/
  rotate_luks_password/
```

The top-level playbook will include summary header documentation covering purpose, supported operating systems, required vaulted variables, role selection variables, tags, example usage, failure handling expectations, and post-run vault maintenance.

## Playbook Controls

All rotations run by default. Operators can run a subset with boolean variables or Ansible tags.

Default variables:

```yaml
rotate_root_password: true
rotate_grub_password: true
rotate_luks_password: true
```

Tags:

```text
root
grub
luks
```

The boolean variables are intended for simple playbook-driven skips. Tags are intended for targeted operator reruns after a partial failure.

## Vault Data Model

Credential data will be stored as structured vaulted records. The playbook will not print secret values.

```yaml
root_credential:
  current: "existing root password"
  new: "new root password"
  prior: "previous root password before current"
  current_changed_at: "YYYY-MM-DD"
  prior_changed_at: "YYYY-MM-DD"

grub_credential:
  current: "existing GRUB password"
  new: "new GRUB password"
  prior: "previous GRUB password before current"
  current_changed_at: "YYYY-MM-DD"
  prior_changed_at: "YYYY-MM-DD"

luks_credential:
  current: "existing LUKS passphrase"
  new: "new LUKS passphrase"
  prior: "previous LUKS passphrase before current"
  current_changed_at: "YYYY-MM-DD"
  prior_changed_at: "YYYY-MM-DD"
```

For each enabled rotation, the matching credential record must define `current`, `new`, `prior`, `current_changed_at`, and `prior_changed_at`.

The playbook validates complexity for each enabled `new` value:

- at least 15 characters
- at least one uppercase letter
- at least one lowercase letter
- at least one number
- at least one symbol

At the end of a fully successful run, the playbook will remind operators to update the encrypted vault record manually:

```text
prior = old current
prior_changed_at = old current_changed_at
current = new
current_changed_at = rotation date
new = next planned password
```

Automatic vault rewriting is out of scope.

## Preflight Validation

Before rotation, the playbook will validate:

- the target OS is RHEL 8, RHEL 9, Ubuntu 22.04, or Ubuntu 24.04
- privilege escalation is available
- required vaulted records and fields are present for enabled rotations
- enabled new passwords satisfy complexity rules
- required utilities are present for enabled rotations

Required utilities include the relevant platform commands for account management, root password aging, GRUB password hashing/config generation, LUKS discovery, and LUKS key management. The roles should fail early with clear messages if required commands are unavailable rather than installing packages on hardened hosts.

## Root Password Role

`roles/rotate_root_password` will update only the `root` account password using `root_credential.new`.

The role will:

- set the root password
- mark root's password as changed on the rotation date
- check root password aging
- ensure root max-days aging is `60`
- report a non-fatal warning if max-days was not already `60` and had to be corrected

The role will not change global password policy and will not rotate any non-root accounts.

## GRUB Password Role

`roles/rotate_grub_password` will use the standard GRUB2 password mechanism.

The role will:

- generate a GRUB PBKDF2 SHA-512 password hash on the managed host from `grub_credential.new`
- write the platform-appropriate GRUB authentication configuration
- regenerate GRUB configuration with the correct RHEL or Ubuntu command/path
- report command failures with the failed step and suggested operator action

Site-specific GRUB templates and non-standard bootloader authentication schemes are out of scope.

## LUKS Password Role

`roles/rotate_luks_password` will auto-discover active LUKS encrypted mappings and rotate each discovered backing device.

The role will:

- discover active LUKS mappings from system block-device and cryptsetup data
- resolve each mapping to its backing encrypted device
- add `luks_credential.new` using `luks_credential.current`
- verify the new passphrase where practical
- remove `luks_credential.current` after the new passphrase has been added and verified
- report failures with host, mapping, backing device when known, failed step, and suggested operator action

Inventory allowlists, automatic handling of inactive encrypted devices, and automatic package installation are out of scope.

## Failure Reporting

Each role will use explicit task names and guarded command blocks so failures are understandable at the end of the playbook.

The final host-level summary will include:

- successful rotations
- skipped rotations
- warnings
- failures
- affected LUKS mapping/device for LUKS failures when known
- a reminder to update vault records after fully successful rotations

Failed hosts should be easy to identify so operators can investigate and decide whether to use the new, current, or prior credential values from vault.

Secret values must not appear in normal task output, failure summaries, debug output, logs, or final recap messages.

## Testing Strategy

Static validation:

- YAML syntax validation
- `ansible-playbook --syntax-check`
- `ansible-lint` where available

Preflight validation tests should cover:

- missing credential records or fields
- weak new passwords
- unsupported OS versions
- missing required commands

Role validation should stay practical:

- root role checks should verify intended account and aging behavior, including warning behavior when max-days is corrected
- GRUB and LUKS task structure should be check-mode-friendly where possible
- destructive GRUB and LUKS behavior should be validated in disposable RHEL 8, RHEL 9, Ubuntu 22.04, and Ubuntu 24.04 VMs with snapshots and encrypted disks

Local CI should not pretend to safely mutate bootloader configuration or disk encryption on the development host.

## Explicitly Out Of Scope

- automatic Ansible Vault rewriting
- inventory LUKS allowlists
- inactive encrypted device rotation
- site-specific GRUB templates
- multi-user password rotation
- installing missing packages on hardened hosts
- global password policy changes
- support for operating systems outside RHEL 8, RHEL 9, Ubuntu 22.04, and Ubuntu 24.04
