"""Generate a cryptographically secure secret on the target host, or reuse
one already generated there.

Runs on the remote target (like any Ansible module). If a secret file
already exists at path/name it's read back unchanged; otherwise a new
random value is generated with the stdlib `secrets` module (CSPRNG,
os.urandom-backed) and written atomically. This replaces the manual
`command ... creates:` + `slurp` composition with a single idempotent step,
and additionally injects the result as an Ansible fact so it's usable
without a `register`.
"""

import os
import secrets
import string
import tempfile

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
---
module: remote_secret
short_description: Generate or reuse a cryptographically secure secret on the target host
version_added: 1.0.0
description:
  - Checks whether a secret file already exists at C(path)/C(name) on the
    target. If it does (and I(force) is not set), its contents are read
    back unchanged. Otherwise a new secret is generated using Python's
    C(secrets) module (a CSPRNG) and written atomically.
  - The secret is returned both as a plain result key and injected as an
    Ansible fact named C(<name>_secret), so it is usable in later tasks as
    C(ansible_facts.<name>_secret) without a C(register). Current
    ansible-core versions also expose it as a bare top-level variable
    (C(<name>_secret)), but that auto-injection is deprecated and slated
    for removal in ansible-core 2.24 -- prefer the C(ansible_facts.)
    prefixed form in new code.
  - Callers B(must) set C(no_log=true) on any task invoking this module,
    since the secret value is returned in plain text and Ansible cannot
    redact it for you without discarding the return value itself.
options:
  name:
    description:
      - Logical name of the secret. Used as the filename under C(path),
        and to build the returned fact name C(<name>_secret).
      - Must not contain C(/) or C(..).
    type: str
    required: true
  path:
    description:
      - Directory the secret file is stored in. Created automatically
        (mode C(0700)) if it doesn't exist yet.
      - The default (C(/root/secrets)) is only readable/writable by root,
        so the task needs C(become=true) (or an equivalent way of running
        as root) unless C(path) is overridden to a directory the
        connecting/become user can already access.
    type: path
    default: /root/secrets
  length:
    description:
      - Number of characters in the generated secret. Ignored when an
        existing secret is being reused.
    type: int
    default: 32
  charset:
    description:
      - Named character set to draw the secret from. Ignored if C(chars)
        is given.
    type: str
    choices: [alphanumeric, hex, urlsafe, ascii, digits, letters]
    default: alphanumeric
  chars:
    description:
      - Literal set of characters to draw the secret from, overriding
        C(charset). Duplicate characters are ignored (deduplicated) since
        they would otherwise bias the distribution.
    type: str
  force:
    description:
      - Regenerate the secret even if a file already exists at C(path)/C(name).
    type: bool
    default: false
extends_documentation_fragment:
  - files
notes:
  - The default C(path) (I(/root/secrets)) requires root privileges to
    read, write, and create. Add C(become=true) to the task, or point
    C(path) at a directory the task's user can already access.
author:
  - Sebastian Faul (@0xFaul)
"""

EXAMPLES = r"""
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

- name: Force-regenerate a secret for this run
  faul.utils.remote_secret:
    name: db_password
    force: "{{ force_secret_regeneration | default(false) }}"
  no_log: true

- name: Generate a hex secret in a custom location
  faul.utils.remote_secret:
    name: api_token
    path: /etc/myapp/secrets
    charset: hex
    length: 64
  no_log: true
"""

RETURN = r"""
path:
  description: Full path (directory + name) of the secret file on the target.
  type: str
  returned: always
<name>_secret:
  description:
    - The secret value. The actual key name is C(<name>_secret), where
      C(<name>) is the module's C(name) parameter (e.g. C(name=db_password)
      returns C(db_password_secret)).
    - Also injected as an Ansible fact via C(ansible_facts), so it's
      readable as C(ansible_facts.<name>_secret) in later tasks without
      C(register).
  type: str
  returned: always
"""

_CHARSETS = {
    "alphanumeric": string.ascii_letters + string.digits,
    "hex": string.digits + "abcdef",
    "urlsafe": string.ascii_letters + string.digits + "-_",
    "ascii": string.ascii_letters + string.digits + "!@#%^&*()-_=+",
    "digits": string.digits,
    "letters": string.ascii_letters,
}


def _dedupe(chars):
    return "".join(dict.fromkeys(chars))


def _resolve_alphabet(module):
    if module.params["chars"]:
        alphabet = _dedupe(module.params["chars"])
    else:
        alphabet = _CHARSETS[module.params["charset"]]

    if len(alphabet) < 2:
        module.fail_json(msg="alphabet must contain at least 2 distinct characters")

    return alphabet


def _validate_name(module, name):
    if not name or "/" in name or ".." in name:
        module.fail_json(msg="name must be a plain filename: no '/' and no '..'")


def _generate_secret(length, alphabet):
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _write_secret(directory, full_path, secret):
    fd, tmp_path = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(secret)
        os.replace(tmp_path, full_path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type="str", required=True),
            path=dict(type="path", default="/root/secrets"),
            length=dict(type="int", default=32),
            charset=dict(
                type="str",
                choices=list(_CHARSETS.keys()),
                default="alphanumeric",
            ),
            chars=dict(type="str"),
            force=dict(type="bool", default=False),
        ),
        add_file_common_args=True,
        supports_check_mode=True,
    )

    name = module.params["name"]
    directory = module.params["path"]
    length = module.params["length"]
    force = module.params["force"]

    _validate_name(module, name)

    if not 1 <= length <= 4096:
        module.fail_json(msg="length must be between 1 and 4096")

    alphabet = _resolve_alphabet(module)
    full_path = os.path.join(directory, name)

    changed = False

    directory_exists = os.path.isdir(directory)
    if not directory_exists:
        changed = True
        if not module.check_mode:
            os.makedirs(directory, exist_ok=True)
            os.chmod(directory, 0o700)

    secret_exists = os.path.exists(full_path)

    if secret_exists and not force:
        with open(full_path, "r") as f:
            secret = f.read()
    else:
        changed = True
        secret = _generate_secret(length, alphabet)
        if not module.check_mode:
            _write_secret(directory, full_path, secret)

    if not module.check_mode:
        if module.params["mode"] is None:
            module.params["mode"] = "0600"
        file_args = module.load_file_common_arguments(module.params, path=full_path)
        changed = module.set_fs_attributes_if_different(file_args, changed)

    fact_key = "{0}_secret".format(name)
    result = {
        "changed": changed,
        "path": full_path,
        "ansible_facts": {fact_key: secret},
        "secret": secret,
    }
    module.exit_json(**result)


if __name__ == "__main__":
    main()
