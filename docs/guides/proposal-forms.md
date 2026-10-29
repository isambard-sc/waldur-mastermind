# Proposal application forms (Formbricks)

Fork-only. The `waldur_mastermind.proposal_forms` app lets a call take its
applications through a chain of [Formbricks](https://formbricks.com) surveys,
a **flow**, instead of Waldur's own proposal form. Answers come back by
webhook and are kept per step; a step can also copy answers onto the proposal
(its name, summary) and request resources from the call's offerings.

Everything is configured through the API: there are no deployment settings.

## Switching it on

Two switches, both needed before any call can take applications this way:

- the feature **`proposal.formbricks_forms`** (staff, in the features admin):
  HomePort shows the Formbricks settings, the flows and each call's flow
  choice only while it is on;
- the connection's **`enabled`**, which staff can only set once the
  connection is configured.

While either is off, calls report `form_flow: null` (so applicants get
Waldur's own form), a flow cannot be chosen for a call, starting or editing an
application is refused, the survey-ending redirect returns the applicant to
the proposal, and the webhook acknowledges (200) and ignores what it is sent,
so Formbricks neither retries nor fails its endpoint test. Staff
can still configure the connection and the flows, so a site can be set up
before it is switched on. Answers already given stay readable.

Each call then opts in by choosing a flow; without one it keeps Waldur's own
form.

## Setting up

1. **Connect the Formbricks server.** As staff, `PATCH /api/formbricks-connection/`:

    | Field | Meaning |
    |-------|---------|
    | `base_url` | Formbricks as applicants' browsers reach it; survey links are built from it |
    | `management_api_url` | Formbricks as this server reaches it, if different (e.g. `http://formbricks:3000`) |
    | `api_key` | Management API key with read access to the flows' surveys and responses |
    | `webhook_secret` | The signing secret Formbricks shows for the webhook (`whsec_...`) |
    | `enabled` | Refused until the URL, key and secret are all set |

    The key and secret are write-only, encrypted at rest, and reported only as
    `api_key_set` / `webhook_secret_set`. Leave one out to keep it; send `""` to
    clear it. `POST /api/formbricks-connection/test/` checks the key works.

2. **Add the webhook in Formbricks** for the environment holding the surveys:
   the URL is `webhook_url` from the connection, with the trigger
   "Response finished". Copy its signing secret into `webhook_secret`.
   Formbricks' "Test endpoint" button posts `{"event": "testEndpoint"}`,
   signed with a secret it only shows after saving, so Waldur acknowledges
   that test without checking it. The URL must be one Formbricks' server can
   reach: from inside a Formbricks container, `localhost` is Formbricks
   itself (a POST there answers 405).

3. **Create the flows.** Through `POST /api/form-flows/`, or from YAML with
   `waldur import_form_flows <file> [--dry-run]` (`export_form_flows` writes
   the same format). `proposal_forms/examples/airr_form_flows.yaml` has the
   AIRR flows, with the development instance's survey ids.

4. **Check each flow** with `POST /api/form-flows/<uuid>/check/`. It reports,
   per step, whether the survey exists, declares the hidden fields, and has
   every question the step maps, and gives the `ending_url` to set as the
   survey's ending ("Redirect to URL").

5. **Switch on** the `proposal.formbricks_forms` feature and the
   connection's `enabled`.

6. **Choose a call's flow:** `PUT /api/proposal-form-calls/<call_uuid>/` with
   `{"flow": "<flow uuid>"}` (or `null` for Waldur's own form). Anyone who may
   update the call may do this until the call has proposals. The flow's
   resource choices must name offerings the call requests.

### What each survey needs

- **Hidden fields** `proposal_uuid` and `redirect_token` (and optionally
  `call_uuid`, `round_uuid`, `lead_name`, `lead_email`, which help find
  responses inside Formbricks).
- **Ending**: "Redirect to URL" set to the step's `ending_url` from the flow
  check, which takes the applicant on to the next unanswered step and finally
  back to the proposal in HomePort.

## Flow steps

```yaml
- key: project_details          # stable id; answers are filed under it
  label: Project details        # shown to applicants and reviewers
  survey_id: cmt4q1c400004qe01zta9vmnm
  reviewer_visible: true        # reviewers may read this step's answers
  field_map:                    # question id -> name | description | project_summary
    fjxcnvv5q1ny48q2wazmq2eb: name
  resources:                    # at most one step per flow
    question_id: peoi4op1vjaws6c2dvigbahe
    options:
      - label: Isambard-AI      # the choice's text in Formbricks, exactly
        offering_slug: isambard-a-1
        attribute_map: {u3bpmiiaumhqqhjk9yrdet6u: allocation}
```

Unknown keys are refused, so a misspelling cannot be silently ignored. A step
that applicants have answered cannot be removed or renamed; its survey id can
change.

## Applying

| Call | Who | What |
|------|-----|------|
| `POST /api/proposal-forms/start/` `{round_uuid}` | anyone eligible for the call | Creates a draft proposal with the caller as manager; returns the first survey link |
| `GET /api/proposal-forms/<proposal_uuid>/` | anyone who can see the proposal | Steps done, the next survey link (for the team, while a draft), and the answers |
| `GET /api/proposal-forms/<proposal_uuid>/edit-link/?step=` | the team, while a draft | A survey link prefilled with the current answers |

Reviewers see only `reviewer_visible` steps; the proposal's team, those
overseeing the call, staff and support see them all. The proposal is then
submitted as any other.

## Security

- The webhook is refused unless signed with the configured secret (Standard
  Webhooks: the secret is base64-decoded, with or without `whsec_`; the
  timestamp must be within five minutes). With no secret set, every webhook is
  refused.
- A signature only proves the request came through Formbricks, where anyone
  can fill in a survey. So the answers must also carry a `redirect_token`
  issued by Waldur for that proposal to someone still on its team, and the
  proposal must still be a draft. The token is not stored with the answers.
- The redirect endpoint authenticates only by that token, and the token
  authenticates nothing else.
- Neither the secret nor the signature expected is ever logged.
