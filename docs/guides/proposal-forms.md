# Proposal application forms (Formbricks)

Fork-only. The `waldur_mastermind.proposal_forms` app adds extra application
forms to a call, kept in [Formbricks](https://formbricks.com): compliance,
team details, technical assessment questions and the like. Everything Waldur
itself reads (applicant, title, summary, resources, duration) stays in
Waldur's own proposal form; the Formbricks forms are stored and shown, never
copied onto the proposal.

Everything is configured through the API: there are no deployment settings.

## How it works

1. The applicant creates a proposal with Waldur's normal form.
2. If the call has a **form flow**, the proposal page lists its forms. "Fill
   in" asks Waldur for a link: Waldur gets a **single-use link** from
   Formbricks and records its id against the proposal and form.
3. The survey carries one hidden field, `proposal_uuid`, only as a label for
   staff browsing Formbricks. It ends by sending the applicant back to the
   proposal in HomePort.
4. The response reaches Waldur by **webhook** and by **fetching** (when the
   applicant comes back, from a "Fetch responses" button, and every 15
   minutes for links still waiting). Either way it is matched to the
   proposal and form **only by its single-use link id**.
5. Reopening a link resumes a form left half-done. Editing an answered form
   gets a new link, prefilled; once the new response is in Waldur, the old
   one is deleted in Formbricks (one copy of the answers there, one here).
6. A proposal cannot be submitted until every form is answered. After
   submission no links are issued and applicants see their answers
   read-only. A correction made in Formbricks by staff still reaches Waldur
   (Formbricks is the source of truth).
7. Deleting a draft proposal deletes its responses in Formbricks.

## Switching it on

Two switches, both needed:

- the feature **`proposal.formbricks_forms`** (staff, in the features admin):
  HomePort shows the Formbricks settings, the flows and each call's flow
  choice only while it is on;
- the connection's **`enabled`**, which staff can only set once the
  connection is configured.

While either is off, calls report `form_flow: null`, a flow cannot be chosen
for a call, no links are issued, submission is not held back by forms, and
the webhook acknowledges (200) and ignores what it is sent. Staff can still
configure the connection and the flows. Answers already given stay readable.

## Setting up

1. **Connect the Formbricks server.** As staff, `PATCH /api/formbricks-connection/`:

    | Field | Meaning |
    |-------|---------|
    | `base_url` | Formbricks as applicants' browsers reach it |
    | `management_api_url` | Formbricks as this server reaches it, if different (e.g. `http://formbricks:3000`) |
    | `api_key` | A **write**-scoped Management API key for the project and environment holding the surveys |
    | `webhook_secret` | The signing secret Formbricks shows for the webhook (`whsec_...`) |
    | `enabled` | Refused until the URL, key and secret are all set |

    The key and secret are write-only, encrypted at rest, and reported only as
    `api_key_set` / `webhook_secret_set`. `POST /api/formbricks-connection/test/`
    checks the key and says how many surveys it can see.

2. **Add the webhook in Formbricks** in the same environment as the surveys:
   the URL is `webhook_url` from the connection, triggers "Response
   finished" and "Response updated", all surveys. Copy its signing secret
   into `webhook_secret`. Its "Test endpoint" button is always answered 200.

3. **Create a flow**: `POST /api/form-flows/`, choosing surveys from
   `GET /api/formbricks-surveys/`; or from YAML with
   `waldur import_form_flows <file> [--dry-run]` (`export_form_flows` writes
   the same format; `proposal_forms/examples/airr_form_flows.yaml` has the
   AIRR flows).

4. **Check, then sync it.** `GET /api/form-flows/<uuid>/check/` reports, per
   survey, what Waldur would change and anything it cannot fix (not a link
   survey, not published, unreachable by the key). `POST .../sync/` (staff)
   then makes each survey ready, changing only:
   - single-use links: on, unencrypted;
   - the `proposal_uuid` hidden field (other hidden fields are kept);
   - every ending: a redirect back to the proposal, keeping its id;
   - "anonymize responses", on Formbricks versions that have it (after 4.9).

   Formbricks merges an update into the survey, so nothing else is written.
   Only surveys that are a step of a flow are ever changed. Sync also stores
   each survey's questions on the flow.

5. **Switch on** the feature and the connection's `enabled`.

6. **Choose a call's flow:** `PUT /api/proposal-form-calls/<call_uuid>/`
   with `{"flow": "<flow uuid>"}` (or `null`), by anyone who may update the
   call, until the call has proposals.

## Flow steps

```yaml
- key: compliance          # stable id; answers are filed under it
  label: Compliance        # shown to applicants and reviewers
  survey_id: ope97ipn9deow44v0icbkgtl
  reviewer_visible: false  # may reviewers read these answers?
```

Unknown keys are refused. A step that applicants have answered cannot be
removed or renamed; its survey id can change.

## Applying

| Call | Who | What |
|------|-----|------|
| `GET /api/proposal-forms/<proposal_uuid>/` | anyone who can see the proposal | Each form's state (`completed`, `submitted_at`, `in_progress`), `missing`, `can_fill_in`, and the answers |
| `POST /api/proposal-forms/<proposal_uuid>/link/` `{step}` | the team, while a draft | A single-use link to fill in, resume or edit the form |
| `POST /api/proposal-forms/<proposal_uuid>/fetch/` | anyone who can see the proposal | Bring the answers up to date from Formbricks |

Reviewers see only `reviewer_visible` forms; the team, those overseeing the
call, staff and support see them all. Submission is refused with
`{"forms": [...]}` naming the forms still to answer.

Survey endings point at `/api/proposal-form-return/?survey=...&proposal_uuid=...`,
which redirects to `<HomePort>/proposals/<uuid>/?form_survey=<survey id>`,
so HomePort can fetch on the applicant's return.

## Security

- A response is trusted only through its single-use link id, issued by
  Waldur for one proposal and form and recorded: hidden fields, which anyone
  can type into a survey link, are never trusted. Each link takes one
  response.
- The webhook is refused unless signed with the configured secret (Standard
  Webhooks: the secret is base64-decoded, with or without `whsec_`; the
  timestamp must be within five minutes). With no secret set, every webhook
  is refused. Neither the secret nor the expected signature is logged.
- No personal data goes in survey links. With anonymised responses on,
  Formbricks keeps no page URL, browser or country either.
- Waldur deletes in Formbricks only responses whose ids it recorded from its
  own links (superseded by an edit, or of a deleted draft), and never
  surveys. Every survey change is logged.
