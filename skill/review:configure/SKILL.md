---
name: review:configure
description: Configure the Witness review adapter, recipe, and evidence policy.
---

# Configure Witness review

Run:

```sh
witness review configure
```

This writes the active configuration at
`$XDG_CONFIG_HOME/review/config.json`, or `~/.config/review/config.json` when
XDG_CONFIG_HOME is unset or empty. The file contains only an adapter
descriptor, a recipe identifier, and a policy. If the file is absent, review
already selects the bundled simple defect-plus-economy configuration and does
not create a file until this command is explicitly used.

Before writing a selection, the command validates the implementation. The
bundled `simple` adapter must have usable `delegate` and `agentbus` commands.
A custom adapter must name its own skill or executable; a custom executable
must pass `<executable> --validate`. A failed validation is an error and leaves
the prior or absent configuration untouched. An invalid present configuration
is never replaced by defaults.

Examples:

```sh
witness review configure -recipe defect-and-economy
witness review configure -require-transcript
witness review configure -adapter local-review -adapter-executable /path/to/local-review
```

Custom adapter behavior belongs to that adapter's skill or executable. This
configuration command does not provide a plugin registry or invent a Go
adapter interface.
