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
3. The survey carries three hidden fields, `proposal_uuid`, `call_uuid` and
   `round_uuid`, only as labels for staff browsing or analysing responses in
   Formbricks (an applicant can edit them in the link, so Waldur never reads
   them back). It ends by sending the applicant back to the proposal in
   HomePort.
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

While either is off, no links are issued, a flow cannot be chosen for a
call, and the webhook acknowledges (200) and ignores what it is sent. Staff
can still configure the connection and the flows. Answers already given stay
readable.

The two switches differ in one way. With the connection disabled (or
Formbricks unreachable), a call with a flow still shows it and still refuses
submission until every form is answered: applicants wait rather than submit
without their forms. Only switching the feature off releases the rule: calls
then report `form_flow: null` and are submitted with Waldur's form alone.

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
   - the `proposal_uuid`, `call_uuid` and `round_uuid` hidden fields (other
     hidden fields are kept);
   - every ending: a redirect back to the proposal, keeping its id.

   On Formbricks versions that have it, also turn on "Anonymize responses"
   in the survey's settings by hand (Formbricks then keeps no page URL,
   browser or country with each response). Sync leaves it alone: Formbricks
   4.9 reports the setting but does not keep it.

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
- No personal data goes in survey links. With "Anonymize responses" on (by
  hand, where Formbricks has it), Formbricks keeps no page URL, browser or
  country either.
- Waldur deletes in Formbricks only responses whose ids it recorded from its
  own links (superseded by an edit, or of a deleted draft), and never
  surveys. Every survey change is logged.

## End-of-project forms

A flow's `purpose` is `application` (filled in for a proposal, as above) or
`closing`: filled in by a project's PI when the project ends. The answers
belong to the project, never to a proposal, so the two never mix.

### Which projects get them

1. A project created from a proposal uses the **closing flow of the call**
   that granted it, if that call has one:
   `PUT /api/proposal-form-calls/<call_uuid>/` with `closing_flow` and
   `closing_forms_open_days_before_end`. The closing flow can change until a
   project of the call has started its forms (`closing_locked`).
2. Otherwise, it uses the **site's closing flow**, if the site has one and it
   applies to the project's organisation: `PATCH /api/site-closing-form-flow/`
   (staff) with `flow`, `closing_forms_open_days_before_end` and `customers`
   (organisations; empty means every organisation). This covers projects no
   call created, such as awards made before calls were used.

A project with no end date never opens its forms.

### When and who

The forms open `closing_forms_open_days_before_end` days before the project's
end date (0: on the day) and stay open for as long as the project exists, so
answers can still be given or edited after the end.

- **Fill in:** the project's PI (project managers) and owners of its
  organisation, i.e. whoever holds `PROJECT.CREATE_PERMISSION` on the project
  or its organisation. Staff too.
- **Read:** those, plus the managers of the call that granted the project,
  and staff and support. Not reviewers.

The PIs are emailed once when the forms open
(`proposal.closing_forms_open`, registered and enabled by migration). A
project whose forms opened more than a week before the site started sending
them is not emailed, so switching the feature on does not email the PI of
every project that ended long ago.

### API

| Call | What |
|------|------|
| `GET /api/project-forms/<project_uuid>/` | State (`opens_on`, `is_open`, `can_fill_in`, steps, `missing`) and the answers; 400 if the project has no end-of-project forms |
| `POST /api/project-forms/<project_uuid>/link/` `{step}` | A single-use link, once open |
| `POST /api/project-forms/<project_uuid>/fetch/` | Bring the answers up to date |

Links carry IDs only: `project_uuid`, and `proposal_uuid`, `call_uuid` and
`round_uuid` when a call granted the project. The survey's endings return to
`<HomePort>/projects/<uuid>/?form_survey=<survey id>`. Deleting the project
deletes its answers, in Waldur and in Formbricks.

### Setting up (the AIRR end-of-project survey)

1. Create a flow with `purpose: closing` whose step is the survey
   (`cms6adb6t0007uk01zr97jsxc` for AIRR).
2. Check and sync it. Sync adds the ID hidden fields and points every ending
   at the project page. The fields the HomePort-only version used
   (`project_name`, `project_slug`, `user_name`, `user_email`,
   `call_reference`) are no longer set by Waldur and are never shown as
   answers; remove them from the survey in Formbricks when convenient.
3. Choose it as the site's closing flow (for existing awards, perhaps
   limited to the AIRR organisations), and/or as calls' closing flows.

A survey cannot be a step of both an application flow and a closing flow,
since its endings can return to only one kind of page: check reports it and
sync leaves it alone. Use a copy of the survey instead.
