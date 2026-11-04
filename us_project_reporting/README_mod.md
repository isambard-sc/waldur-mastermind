# Scripts

## new_project_users_mod.py

Generates a list of users on active Isambard-AI projects who need to be onboarded to Bristol Portal (i.e. need an AWS account set up for them).

### Background

There are two connected Waldur portals:

- **AIRRPortal** — `https://portal-airr-api.isambard.ac.uk`. Users join projects here. Projects are submitted to Bristol Portal for approval and may have an `earliest_approve` embargo date before they can be confirmed.
- **Bristol Portal** — receives projects from AIRRPortal and approves them. Users need an AWS account to log in here.

The script covers two cases to ensure no one is missed:

1. **Projects that recently became active in Bristol Portal** — captures all current members, including those who joined AIRRPortal earlier but were waiting on an embargo to lift.
2. **Projects already active in Bristol Portal** — captures members who joined AIRRPortal recently.

### First-time setup

Install `uv` if you don't have it:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

That's all — `uv` handles creating a virtual environment and installing dependencies automatically on first run.

### Running

```bash
uv run new_project_users_mod.py
```

The script will prompt for:

1. Your AIRRPortal API token (or read it from `WALDUR_TOKEN`)
2. How many days back to look (1–7, default 1)

```bash
# Pass the AIRRPortal token directly
uv run new_project_users_mod.py --token <your-token>

# Or via environment variable
WALDUR_TOKEN=<your-token> uv run new_project_users_mod.py
```

The "days back" input is day-granular, not a rolling window. With `days=1` at 14:00 UTC, the script looks back to midnight yesterday (~38 hours of coverage).

### Output

Tab-separated user rows go to stdout; all progress messages go to stderr. To copy the data to the clipboard while also seeing it in the terminal:

```bash
# WSL
uv run new_project_users_mod.py | tee /dev/tty | clip.exe

# macOS
uv run new_project_users_mod.py | tee /dev/tty | pbcopy

# Linux (X11)
uv run new_project_users_mod.py | tee /dev/tty | xclip -selection clipboard

# Linux (Wayland)
uv run new_project_users_mod.py | tee /dev/tty | wl-copy
```

Redirect to a file if needed:

```bash
uv run new_project_users_mod.py > results.tsv
```

> **Note:** The current version also checks each user against the Keycloak realm and splits the output into those who already have an account and those who do not. This check is for development/testing only and will be removed from the final version.

### Requirements

- An AIRRPortal API token with permission to read users, project memberships, RemoteProjects, and the RemoteProject audit log
- *(Dev/test only)* A Keycloak account with the `view-users` role assigned in the Isambard realm, and a browser reachable from the machine you're running the script on (needed for the device-flow login step)

### Notes

- The Keycloak URLs currently point at `keycloak-dev` and will be updated to production at a later date.
- Projects that became active within the window but have since been deleted or errored will produce a `WARNING` line in the output and their members will be skipped.
