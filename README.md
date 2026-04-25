# rotateCredentials

Ansible playbook and roles for rotating Linux root, GRUB, and active LUKS
full-disk-encryption credentials. The playbook coordinates preflight checks,
scopes enabled rotations, runs the root, GRUB, and LUKS roles, and prints a
sanitized per-host summary without exposing credential values.

## Supported Managed Hosts

- RHEL 8
- RHEL 9
- Ubuntu 22.04
- Ubuntu 24.04

This project is intended for hardened Linux estates, including FIPS/STIG-style
hosts where package installation is controlled separately. The playbook checks
for required platform commands, but it does not install missing packages. Hosts
missing required tools fail preflight and should be remediated through the
normal system build or package management process.

## Vaulted Credential Records

Store real credentials in Ansible Vault. Use
`group_vars/vault.example.yml` only as the shape for the encrypted data file;
it contains non-secret sample values and is not auto-loaded as a real vault
source.

Real vault variables must be loaded explicitly, for example:

```bash
ansible-playbook rotate_credentials.yml \
  --ask-vault-pass \
  --extra-vars @path/to/vault.yml
```

Each enabled rotation requires its matching credential record with these fields:

- `current`
- `new`
- `prior`
- `current_changed_at`
- `prior_changed_at`

The records are:

```yaml
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

For every enabled rotation, the `new` value must satisfy the playbook
complexity rule: at least 15 characters with uppercase, lowercase, number, and
symbol characters.

## Running The Playbook

Basic run against the configured inventory:

```bash
ansible-playbook rotate_credentials.yml \
  --ask-vault-pass \
  --extra-vars @path/to/vault.yml
```

To target a specific inventory file:

```bash
ansible-playbook -i inventory rotate_credentials.yml \
  --ask-vault-pass \
  --extra-vars @path/to/vault.yml
```

By default, all three rotation booleans are enabled in `group_vars/all.yml`:

- `rotate_root_password: true`
- `rotate_grub_password: true`
- `rotate_luks_password: true`

Run only root rotation by disabling the other rotation groups:

```bash
ansible-playbook rotate_credentials.yml \
  --ask-vault-pass \
  --extra-vars @path/to/vault.yml \
  -e rotate_grub_password=false \
  -e rotate_luks_password=false
```

Run only GRUB rotation with tags:

```bash
ansible-playbook rotate_credentials.yml \
  --ask-vault-pass \
  --extra-vars @path/to/vault.yml \
  --tags grub
```

Run only LUKS rotation with both tag and boolean scoping:

```bash
ansible-playbook rotate_credentials.yml \
  --ask-vault-pass \
  --extra-vars @path/to/vault.yml \
  -e rotate_root_password=false \
  -e rotate_grub_password=false \
  --tags luks
```

Available tags are `root`, `grub`, and `luks`. Without `--tags`, every enabled
`rotate_*` boolean is active. With `--tags`, only the selected rotation tags are
active, and preflight checks are scoped to those active rotations.

## Post-Run Vault Maintenance

Update the encrypted vault record only after a host has completed every enabled
rotation successfully:

- `prior = old current`
- `prior_changed_at = old current_changed_at`
- `current = new`
- `current_changed_at = rotation date`
- `new = next planned password`

Keep failed hosts under investigation before promoting values in the vault. A
host that fails after a partial rotation may need host-specific recovery before
its vault record is advanced.

The final playbook output is sanitized. It reports successes, warnings, skips,
and summarized failures without printing `current`, `new`, or `prior`
credential values.

## Verification

Run a syntax check before operating on hosts:

```bash
ansible-playbook --syntax-check rotate_credentials.yml
```

If your syntax check needs access to encrypted variables in your environment,
load the real vault explicitly:

```bash
ansible-playbook --syntax-check rotate_credentials.yml \
  --ask-vault-pass \
  --extra-vars @path/to/vault.yml
```

For destructive validation of GRUB and LUKS behavior, use only disposable RHEL
or Ubuntu virtual machines with snapshots and encrypted disks. Do not validate
bootloader or disk-encryption credential rotation against irreplaceable systems.
