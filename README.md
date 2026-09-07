# faul.utils

Small, focused utility modules for Ansible.

## Modules

### `remote_secret`

Generate a cryptographically secure secret on the target host, or reuse one
already generated there. Checks for an existing secret file at `path/name`;
if present (and `force` is not set) its contents are read back unchanged,
otherwise a new secret is generated with Python's `secrets` module (CSPRNG)
and written atomically. Replaces the common `command ... creates:` + `slurp`
composition with a single idempotent step.

```yaml
- name: Generate or reuse the DB password
  faul.utils.remote_secret:
    name: db_password
  become: true  # default path is /root/secrets, which requires root
  no_log: true
  # no `register` needed: ansible_facts.db_password_secret is now usable below

- name: Use the secret
  ansible.builtin.debug:
    msg: "{{ ansible_facts.db_password_secret }}"
  no_log: true
```

See `ansible-doc faul.utils.remote_secret` for the full option reference.

**Callers must set `no_log: true`** on any task invoking this module — the
secret is returned in plain text and Ansible cannot redact it for you
without discarding the return value itself.

**The default `path` (`/root/secrets`) requires root.** Add `become: true`
to the task, or point `path` at a directory the connecting/become user can
already access.

## Installation

Not published to Ansible Galaxy, yet.

```
ansible-galaxy collection install git+https://github.com/0xFaul/ansible-utils.git
```

Or add it to a `requirements.yml`:

```yaml
collections:
  - name: https://github.com/0xFaul/ansible-utils.git
    type: git
    version: main
```

## License

GPL-3.0-or-later
