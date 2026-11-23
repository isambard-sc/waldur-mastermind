# AI reporting

Staff and support users ask questions about Waldur's data in plain English and get an answer, with charts or
files when asked. Claude on Amazon Bedrock (eu-west-2) does the work through a separate service, the harness,
which runs in the cluster. The feature is off until `AI_REPORTING_ENABLED` is switched on.

Deploying the harness is covered by `PROD_CHECKLIST.md` in the harness repo (waldur-ai-harness). This guide
explains how the pieces fit together and how to operate them.

## The pieces

| Piece | Where | What it does |
|---|---|---|
| Homeport | `src/ai-reporting/`, `src/administration/ai-reporting/` | Ask, History, Files and Usage pages; the admin Connection tab |
| Mastermind | `src/waldur_mastermind/ai_reporting/` | The REST API, limits, the Celery task that calls the harness, retention |
| Harness | separate repo, namespace `waldur-harness` | The model loop; the only component that talks to Bedrock or runs code |
| Sandbox | Kubernetes Jobs created by the harness | Runs model-written Python with no network and no credentials |

## A question, end to end

1. **Ask.** Homeport POSTs `/api/ai-reporting-messages/ask/` with the prompt and either the conversation's
   `session` uuid or `new_session: true`. The view checks the role setting and the token limits, then, under
   one site-wide lock, that this user has no question running and that fewer than
   `AI_REPORTING_MAX_CONCURRENT_QUESTIONS` are running. It saves a `pending` `ReportingMessage`, queues the Celery task `ask_harness` and returns 202.
2. **Call the harness.** `ask_harness` checks access again, then POSTs `/query` to the harness URL from
   `HarnessConnection`. The request is signed with Waldur's Ed25519 private key (timestamp, user, path and body);
   the harness holds only the public key and rejects anything unsigned or older than 2 minutes. It carries the
   question, the session uuid and the deadline (540 s).
3. **The model loop.** The harness loads that conversation's history and calls Claude with five tools:
   - `waldur_fetch`: read-only GETs as one shared support account. Sensitive endpoints are blocked, secrets are
     redacted, and the data is saved as a file in the conversation's folder; the model sees only a summary.
   - `waldur_schema`: searches a trimmed copy of the API schema.
   - `code_search`, `code_read`: a snapshot of the mastermind source.
   - `run_code`: model-written Python, run as a one-pod Kubernetes Job with no network, no credentials and only
     that conversation's folder mounted. The admission policy and network policies enforce this even if the
     harness itself is compromised.

   Before each step the harness streams a progress line, with the token totals so far.
4. **Save the answer.** Waldur saves each progress line on the message, so the page can show it. When the answer
   arrives, Waldur downloads each listed file from the harness, checks its name, type (by content) and size,
   then saves the answer, the title, the files and a permanent `ReportingUsageRecord` in one transaction.
5. **Show it.** Homeport polls the message every 3 s until it is `done` or `failed`. Answers are rendered as
   Markdown with raw HTML and images turned off; only links to `AI_REPORTING_LINK_DOMAINS` are clickable. Files
   are served through Waldur's normal media access control, to their owner only.

Waldur treats the harness as untrusted: every line, body and file it returns is size-capped and checked.

## Settings

**Waldur (Constance, AI reporting section):**

| Setting | Default | Meaning |
|---|---|---|
| `AI_REPORTING_ENABLED` | off | Shows the pages and accepts questions |
| `AI_REPORTING_ENABLED_ROLES` | staff and support | Who may use it (there is no all-users option) |
| `AI_REPORTING_NAME` | Isambard Reporting Assistant | The assistant's name in its answers |
| `AI_REPORTING_CUSTOM_INSTRUCTIONS` | empty | Extra text added to the system prompt |
| `AI_REPORTING_LINK_DOMAINS` | empty | Domains whose links in answers are clickable |
| `AI_REPORTING_HISTORY_QUESTIONS` | 10 | Earlier questions sent with each new one; -1 for all |
| `AI_REPORTING_MAX_TURNS` | 25 | Steps per question, 1 to 40 |
| `AI_REPORTING_TOKEN_LIMIT_DAILY` | -1 | Tokens per user per rolling day; -1 for unlimited |
| `AI_REPORTING_GLOBAL_DAILY_TOKEN_BUDGET` | 5,000,000 | Tokens per UTC day across all users; -1 for unlimited |
| `AI_REPORTING_MAX_CONCURRENT_QUESTIONS` | 3 | Questions running at once across all users; each holds a Celery worker |
| `AI_REPORTING_MESSAGE_RETENTION_DAYS` | 90 | Days to keep questions and answers; -1 to keep them |
| `AI_REPORTING_FILE_RETENTION_DAYS` | 21 | Days to keep generated files; -1 to keep them |

**Waldur (Administration > AI reporting > Connection):** the harness URL (an in-cluster
`<service>.<namespace>.svc` address only) and the signing private key (write-only, encrypted at rest).

**Harness (ConfigMap):** the model (`WALDUR_AGENT_MODEL`, which must match the IAM policy), the sandbox image by
digest, the signing public key, `SESSION_RETENTION_DAYS`, `MAX_CONCURRENT_RUNS` (keep it at least Waldur's
concurrency limit), and `SANDBOX_DEDICATED_NODES` / `SANDBOX_RUNTIME_CLASS` for the sandbox node pool.

## Time limits

Waldur owns each question's deadline. The harness gets a shorter one, so its "ran out of time" answer arrives
before Waldur gives up.

| Where | Limit | Value | Stops |
|---|---|---|---|
| Waldur | Question deadline | 600 s from the task's start | A question running for ever |
| Waldur | Gap between stream lines | 360 s | A harness that stops sending |
| Waldur | File downloads | 60 s each, 180 s in all | Slow downloads |
| Waldur | Celery soft / hard limit | 1200 / 1800 s | Any task overrunning |
| Waldur | Stale check | no progress for 15 min, checked every 10 min | A question left pending by a lost worker |
| Waldur | Harness delete retries | 60 s doubling to 1 h, 8 times | A harness busy or down when a conversation is deleted |
| Harness | Run deadline | Waldur's 540 s, capped at 30 to 600 | A run outliving Waldur's wait |
| Harness | One model call | at most 300 s, cut to the time left; not started under 20 s | One hung model call |
| Harness | One `run_code` | at most 30 s, cut to the time left minus 20 s; refused under 10 s | Slow model code |
| Harness | Sandbox Job | `run_code` limit + 15 s; the admission policy allows at most 600 s | A sandbox nobody deleted |
| Harness | Waldur API | 30 s per page; paging stops at the run deadline | A slow Waldur |
| Harness | Request signature | ±120 s | Replay of an old request |

Why they hold together:

- **540 < 600**: the harness answers before Waldur's deadline.
- **300 < 360**: the harness sends progress before every model call, tool and fetched page, so a long call never
  looks like a stalled stream.
- **600 + 360 + 180 + 10 < 1200**: a question always ends before Celery's soft limit.
- **15 min > 360 s**: the stale check never fails a question that is still working.

## When something goes wrong

| The user sees | Likely cause | Where to look |
|---|---|---|
| AI reporting is not available to you. | The feature is off, the user's role isn't allowed, or the account is inactive | Constance settings |
| AI reporting isn't set up yet: the harness signing key is missing. | No private key on the Connection tab | Administration > AI reporting |
| The AI reporting service couldn't answer this question. | Harness unreachable; keys don't match (harness logs a 401); harness error or Bedrock failure | Celery worker log (`ask_harness:`), then `kubectl logs -n waldur-harness deploy/waldur-harness` |
| AI reporting is busy answering other questions. | The concurrency limit (Waldur's or the harness's) is reached | `AI_REPORTING_MAX_CONCURRENT_QUESTIONS`, `MAX_CONCURRENT_RUNS` |
| Wait for your current question to finish before asking another. | This user already has a question running | Wait, or the stale check fails it after 15 minutes |
| This question took too long to answer. | Waldur's deadline passed, or the stream stalled | Harness logs for that time |
| This question was interrupted. | A Celery worker was lost mid-question (deploy, crash) | Worker restarts |
| You've reached your daily AI reporting token limit. / site-wide daily token budget | The token limits | Usage page, Constance limits |
| Answer: "I ran out of time before finishing this question." | The harness deadline | Ask a narrower question |
| Answer: "I ran out of steps before finishing this question." | `AI_REPORTING_MAX_TURNS` | Ask a narrower question, or raise the limit |

## Operating it

**Deploying mastermind:**

1. Run `waldur migrate` on a worker pod; Helm doesn't run migrations.
   `waldur showmigrations ai_reporting` should show `[X] 0001_squashed_0007`.
2. Run `waldur clean_settings_cache`. Waldur caches its public configuration until a setting changes, so
   without this the AI reporting menu can stay hidden after a deploy.

Deploy at a quiet time: a question running while the worker pods are replaced loses its answer. It shows as
"interrupted" once the stale check runs (within 25 minutes), and the user can ask again. To clear it sooner,
once it has had no progress for 15 minutes: `waldur shell -c "from waldur_mastermind.ai_reporting.tasks import
fail_stale_reporting_messages; print(fail_stale_reporting_messages())"`.

**Upgrading the harness:**

1. Build and push the new images with new tags.
2. Put the sandbox image's digest in the ConfigMap.
3. Apply the ConfigMap and the Deployment first, then the admission policies.

The Deployment uses `Recreate`, so questions running during the restart fail as interrupted. Deploy at a quiet
time.

**Rotating the signing key:**

1. Generate a new keypair (command in `signing.py`).
2. Put the public key in the harness ConfigMap and restart the harness.
3. Paste the private key on the Connection tab.

Questions fail between steps 2 and 3, since the harness accepts only one key, so do both quickly.

**Rotating the harness's Waldur token:** create a new token for the harness account, update the Kubernetes
Secret, restart the harness, then revoke the old token.

**What to watch:**

- the harness Deployment not being ready;
- a rise in `failed` messages;
- Bedrock spend (an AWS budget alarm);
- the size of the EFS file system.

**Rollback:** switch `AI_REPORTING_ENABLED` off (the pages disappear and every request is refused), then scale
the harness to zero. `waldur migrate ai_reporting zero` drops the app's tables, before rolling back the code.
