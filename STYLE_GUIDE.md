# Falco Rules Doc Comment Style Guide

> **Status:** Draft — opened in PR for discussion with maintainers.
> Feedback and revisions welcome; this guide is a starting point, not a mandate.

---

## Motivation

Falco rule files contain two kinds of comments: comments that document an
individual item (a rule, macro, or list), and comments that annotate a section
of the file. Without a convention to distinguish them, it's ambiguous whether a
comment describes the item immediately below it or the group that follows.

This guide proposes a small set of lightweight conventions borrowed from the
[Go Doc Comments](https://go.dev/doc/comment) model and shaped by the discussion
in [issue #150](https://github.com/falcosecurity/rules/issues/150). The goal is
to make rule files easier to read, easier to tune, and easier to review — without
imposing heavy overhead on contributors.

The conventions apply to the YAML rule files under `rules/`. They complement
(rather than replace) the [Falco Rules Style Guide](https://falco.org/docs/rules/style-guide/).

---

## 1. Doc Comments vs. Section Comments

This is the central rule. There are exactly two kinds of comments:

- **Doc comment** — documents a single item (rule, macro, list). No blank line
  between the comment and the item.
- **Section comment** — annotates a group of items or a region of the file. Has
  a blank line above it *and* at least one blank line between it and the first
  item in the group.

### Why this matters

Without the blank-line rule, a comment that sits three lines above a macro might
be describing the macro, the previous macro, or a logical group. The blank-line
rule resolves this unambiguously: if there's no blank line between a comment and
an item, the comment belongs to that item.

### GOOD — doc comment (no blank line between comment and item)

```yaml
# True when the event occurs inside a container (container.id != host).
# Used widely to scope rules to containerized workloads only.
- macro: container
  condition: (container.id != host)
```

### BAD — ambiguous gap

```yaml
# True when the event occurs inside a container (container.id != host).

- macro: container
  condition: (container.id != host)
```

The blank line above signals "section comment," but this comment is clearly
about `container`, not a group. A reviewer cannot tell without reading the
condition.

### GOOD — section comment (blank line on both sides)

```yaml
# ─── File access helpers ────────────────────────────────────────────────────

- macro: open_write
  condition: (evt.type in (open,openat,openat2) and evt.is_open_write=true and fd.typechar='f' and fd.num>=0)

- macro: open_read
  condition: (evt.type in (open,openat,openat2) and evt.is_open_read=true and fd.typechar='f' and fd.num>=0)
```

The blank line separating the section comment from the items makes clear it
applies to the group, not specifically to `open_write`.

### BAD — section comment pasted to the first item

```yaml
# File access helpers
- macro: open_write
  condition: (evt.type in (open,openat,openat2) and evt.is_open_write=true and fd.typechar='f' and fd.num>=0)
```

This looks like a doc comment for `open_write` alone, when the intent was to
label the section.

---

## 2. Doc Comment Structure

A doc comment's **first sentence** should summarize what the item does — concise
enough to serve as a tooltip or search result. Additional sentences can cover
tuning guidance, rationale, related items, or caveats.

The first sentence ends at the first period followed by a space or newline.
Don't pad with introductory phrases like "This macro…" or "This list…" — start
with the substance.

### GOOD

```yaml
# Detects process name existence; required before identity-based conditions.
# Handles the edge case of dropped syscall events where proc.name may be "<NA>".
# TODO: Remove the "N/A" variant once scap-file compatibility is no longer needed.
- macro: proc_name_exists
  condition: (not proc.name in ("<NA>","N/A"))
```

- First sentence states the purpose directly.
- Second sentence explains the rationale.
- TODO is explicit and actionable.

### BAD

```yaml
# This macro is about the process name
- macro: proc_name_exists
  condition: (not proc.name in ("<NA>","N/A"))
```

"About the process name" tells a reviewer nothing they couldn't infer from
the macro name itself.

---

## 3. Tuning Macros (`user_*`, `allowed_*`)

Tuning macros are placeholders — their default condition is `(never_true)` or
`(always_true)`, and operators are expected to override them locally to suppress
false positives. Because these macros have no `desc` field, their doc comment is
the *only* documentation an operator will read before deciding how to override.

**Required in every tuning macro doc comment:**

1. What the macro does (one sentence).
2. How to override it — include a concrete `append: true` snippet.
3. The field or fields most commonly used in overrides (e.g., `proc.name`,
   `container.image.repository`).

### GOOD

```yaml
# Suppresses "Read sensitive file untrusted" for known-legitimate readers.
# Default is never_true (no suppression). To allow specific processes, append:
#
#   - macro: user_known_read_sensitive_files_activities
#     condition: (proc.name in (my_backup_agent, my_audit_tool))
#     append: true
#
# Common override fields: proc.name, proc.exepath, container.image.repository.
- macro: user_known_read_sensitive_files_activities
  condition: (never_true)
```

### BAD

```yaml
# Add conditions here to suppress false positives.
- macro: user_known_read_sensitive_files_activities
  condition: (never_true)
```

An operator hitting a false positive at 2 AM needs the override snippet, not
a paraphrase of what overriding means.

---

### GOOD — `allowed_*` style (negative-logic placeholder)

```yaml
# Allowlist of hosts permitted to initiate SSH connections in the monitored rule.
# Default is never_true; the rule uses double negation (and not allowed_ssh_hosts),
# so this macro effectively allows everything when unset.
#
# To restrict SSH to known management hosts:
#
#   - macro: allowed_ssh_hosts
#     condition: (evt.hostname in (bastion.example.com, mgmt.example.com))
#     append: true   # or override entirely — remove append: true to replace default
#
# See also: macro never_true for the placeholder pattern.
- macro: allowed_ssh_hosts
  condition: (never_true)
```

### BAD

```yaml
# Placeholder for SSH host allowlist.
- macro: allowed_ssh_hosts
  condition: (never_true)
```

---

## 4. Lists with Derived Data

When a list's contents were generated or sourced from an external reference
(a package manager query, a vendor document, a command), record that provenance
in the doc comment. This helps future contributors verify and update the list
without having to reverse-engineer how it was built.

### GOOD

```yaml
# Password and account-management binaries on Debian/Ubuntu systems.
# Generated with:
#   dpkg -L passwd | grep bin | xargs ls -ld | grep -v '^d' \
#     | awk '{print $9}' | xargs -L 1 basename | tr '\n' ','
# Last verified against passwd 1:4.13+dfsg1-4 (Debian bookworm).
- list: passwd_binaries
  items: [
    shadowconfig, grpck, pwunconv, grpconv, pwck,
    groupmod, vipw, pwconv, useradd, newusers, cppw, chpasswd, usermod,
    groupadd, groupdel, grpunconv, chgpasswd, userdel, chage, chsh,
    gpasswd, chfn, expiry, passwd, vigr, cpgr, adduser, addgroup, deluser, delgroup
    ]
```

### BAD

```yaml
# passwd binaries
- list: passwd_binaries
  items: [
    shadowconfig, grpck, pwunconv, ...
    ]
```

Without the source command, the next contributor who needs to update this list
for a new distro version has no starting point.

---

### GOOD — vendor / upstream URL attribution

```yaml
# NFS external-provisioner image; sourced from upstream chart values:
# https://github.com/kubernetes-sigs/nfs-subdir-external-provisioner/blob/master/charts/nfs-subdir-external-provisioner/values.yaml
- list: nfs_provisioner_images
  items: [registry.k8s.io/sig-storage/nfs-subdir-external-provisioner]
```

---

## 5. Commented-Out Code

Commented-out rules, macros, and lists accumulate quickly. At scale they become
noise that reviewers skip, and nobody knows whether they were intentionally
disabled, broken, or simply forgotten.

**Convention:** if you keep a commented-out item, its doc comment must explain
*why* it is disabled and under what conditions it should be re-enabled.
If you cannot write that explanation, delete the item — git history preserves it.

### GOOD — intentionally disabled with clear reason

```yaml
# Disabled: read and write syscalls are ignored in the current event source.
# The open_write/open_read macros cover the relevant cases via the open* family.
# Re-enable if a future Falco version surfaces raw read/write as distinct events.
#
# - macro: write
#   condition: (syscall.type=write and fd.type in (file, directory))
# - macro: read
#   condition: (syscall.type=read and fd.type in (file, directory))
```

### BAD — unexplained comment

```yaml
# - macro: write
#   condition: (syscall.type=write and fd.type in (file, directory))
# - macro: read
#   condition: (syscall.type=read and fd.type in (file, directory))
```

A reviewer seeing this has no idea if the macros are intentionally disabled,
temporarily scaffolded, or simply left from a refactor.

---

### GOOD — tuning template with opt-in explanation

```yaml
# Optional: treat any node process in a container as a protected shell spawner.
# Disabled by default because node is also widely used as a build-pipeline tool
# where spawning shells is expected. Enable by overriding this macro to remove
# the never_true guard:
#
#   - macro: possibly_node_in_container
#     condition: (proc.pname=node and proc.aname[3]=docker-containe)
#     # no append: true — replace the default entirely
#
- macro: possibly_node_in_container
  condition: (never_true and (proc.pname=node and proc.aname[3]=docker-containe))
```

---

## 6. Section Comments

Section comments group related items visually. They are separated from the items
they introduce by a blank line (so they are not mistaken for a doc comment on the
first item in the group).

A section comment should describe the logical grouping, not re-list the items.

### GOOD

```yaml
# ─── Shell-spawning protection ───────────────────────────────────────────────
# Macros and lists used by "Run shell untrusted" to identify non-shell parent
# processes that should never spawn a shell.

- list: protected_shell_spawning_binaries
  items: [
    http_server_binaries, db_server_binaries, nosql_server_binaries, mail_binaries,
    fluentd, flanneld, splunkd, consul, smbd, runsv, PM2
    ]

- macro: protected_shell_spawner
  condition: (proc.pname exists and proc.pname in (protected_shell_spawning_binaries))
```

### BAD — section header attached to first item

```yaml
# Shell-spawning protection macros and lists
- list: protected_shell_spawning_binaries
  items: [...]
```

---

## 7. Field Order within a Rule

The [Falco Rules Style Guide](https://falco.org/docs/rules/style-guide/) is
authoritative on field ordering. For reference, the order used in existing
`maturity_stable` rules is:

```yaml
- rule: <name>
  desc: >
    <description>
  condition: >
    <condition>
  output: <output string>
  priority: <PRIORITY>
  tags: [<maturity_tag>, <workload_tags>, <mitre_tags>]
  enabled: <true|false>   # omit when true (the default)
  source: <source>        # omit when syscall (the default)
```

`enabled: false` and `source:` are placed after `tags` and only included when
they differ from the default. This ordering is a convention observed in the
existing rule corpus; defer to maintainers if guidance changes.

---

## Quick Reference

| Situation | Convention |
|-----------|------------|
| Comment immediately precedes an item (no blank line) | Doc comment — documents that item |
| Comment has a blank line before it AND below it | Section comment — labels a group |
| Tuning macro (`user_*`, `allowed_*`) | Doc comment must include override snippet with `append: true` |
| List with generated or sourced content | Doc comment must include source command or URL |
| Commented-out item with no explanation | Delete it — use git history |
| Commented-out item kept intentionally | Doc comment must state why and when to re-enable |
| First sentence of any doc comment | Summarize purpose; avoid "This macro…" preamble |

---

## Relationship to the Existing Style Guide

This guide covers **comment conventions only**. For rule expression style,
output format, tag requirements, and maturity-level criteria, see the
[Falco Rules Style Guide](https://falco.org/docs/rules/style-guide/) and
[CONTRIBUTING.md](CONTRIBUTING.md).

---

*Feedback on these guidelines is welcome in the PR discussion.*
