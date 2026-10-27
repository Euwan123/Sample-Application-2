# Policy Rehearsal

A local-only thesis project for comparing predictions about authentication policies with a replica login service. All account data, passwords, and attack traffic are synthetic. Volunteer login logs are read only from a local CSV that you provide; no volunteer data is included in this project.

This is a research and teaching model, not production authentication software.

## What it does

- Defines one shared policy format for the simulator and FastAPI replica.
- Simulates 36 combinations of threshold, lockout type, MFA, and recovery under three traffic scenarios (108 cells).
- Uses 30 simulator runs and 10 replica runs per cell by default; change these in `simulator/settings.yaml` or override a run count from the command line.
- Writes predictions and a SHA-256 lock before comparison. Comparison refuses a changed or mismatched prediction file.
- Calibrates user settings from 20 volunteers and keeps 10 different volunteers held back for replica replay.
- Compares prediction and replica means, confidence-interval coverage, policy rankings, issue flags, reviewer answers, and SUS scores.
- Includes a Streamlit page for running one simulator cell and viewing a replica result when one is available.

## Project layout

```text
policy-rehearsal/
  policies/policy.yaml
  simulator/
    settings.yaml
    model.py
    run.py
    calibrate.py
  replica/
    service.py
    main.py
    experiment.py
    Dockerfile
  attacks/
    common.py
    brute_force.py
    credential_stuffing.py
    replay_traffic.py
  compare/
    thresholds.yaml
    run.py
  ui/app.py
  data/                 generated local CSV and SQLite files
  tests/
  docker-compose.yml
  requirements.txt
```

## Set up on Windows

Run these commands in PowerShell from the `policy-rehearsal` directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run tests:

```powershell
python -m pytest -q
```

The tests use synthetic fixtures and do not require volunteer data or Docker.

## Policy and settings

`policies/policy.yaml` is the current policy used by the interactive replica:

```yaml
threshold: 5
lockout: fixed
fixed_lock_seconds: 900
mfa: sensitive
recovery: self_service
```

Valid values are thresholds `10`, `5`, or `3`; lockout `fixed` or `progressive`; MFA `none`, `sensitive`, or `all`; and recovery `disabled` or `self_service`. A fixed lock has a configurable `fixed_lock_seconds` duration. The progressive rule allows the threshold number of free failures, then waits 30 seconds, doubling on each further failure up to 3,600 seconds. The experiment now compares 36 policy combinations across three traffic types, producing 108 cells.

Self-service recovery is synthetic: a sample forgotten-password event succeeds according to `users.recovery_success_rate` and adds `users.recovery_delay_seconds`; the replica's `/recover` endpoint uses a synthetic account-specific recovery code. This is only a local teaching mechanism, not a real password reset flow.

`simulator/settings.yaml` contains the synthetic population size, run counts, seed, user behavior, and attacker settings. The starting user settings are `mistype_rate: 0.10` and `forget_rate: 0.004`. The API and batch replica runner both read this settings file.

## Calibrate from volunteer session logs

Prepare a local CSV with one row per login session and these columns. The Streamlit UI also has a built-in synthetic file at `data/sample_login_sessions.csv` to try the workflow without volunteer data.

| Column | Meaning |
|---|---|
| `volunteer_id` | Stable ID grouping sessions from the same volunteer |
| `session_id` | Unique ID for each session |
| `login_attempts` | Total attempts in the session; at least 1 |
| `failed_attempts` | Failed attempts in the session; no greater than `login_attempts` |
| `forgot_password` | `true` or `false` |
| `mfa_challenged` | `true` or `false` |
| `mfa_device_available` | `true` or `false` when observed; may be blank when unavailable/not observed |

The CSV must contain at least 30 distinct volunteers. The seeded split selects 20 volunteers for fitting and 10 separate volunteers for held-out replay. Fitting uses only the 20-volunteer group:

- `mistype_rate`: failed attempts divided by attempts in non-forgotten sessions.
- `forget_rate`: share of fitting sessions marked as forgotten.
- `max_retries`: 95th percentile of fitting-session failed attempts, rounded up.
- `mfa_device_at_hand`: share of observed challenged sessions with a device available.

At least one fitting session must include an observed MFA-device availability value. Other settings are preserved. By default, calibration updates `simulator/settings.yaml` and writes the pseudonymized held-out sessions to `data/heldout_sessions.csv`.

```powershell
python -m simulator.calibrate --input .\data\volunteer_sessions.csv --seed 23
```

Do **not** upload or use username/password lists, raw credentials, tokens, emails, or names. Calibration accepts only the seven documented session-summary columns and rejects extra columns. Keep any real volunteer CSV local and do not commit it. The generated held-out CSV contains only replay fields and pseudonymized volunteer/session IDs.

## Generate simulator predictions

```powershell
python -m simulator.run
```

This runs all 108 cells using the configured simulator run count and writes:

- `data/predictions.csv` — means and 95% confidence intervals for six measures.
- `data/predictions.lock` — SHA-256 digest and expected filename.

You can change `simulation.runs` and `simulation.accounts` in `simulator/settings.yaml`. Optional `--runs` and `--accounts` command-line overrides affect that prediction run only. Treat the locked CSV as fixed after replica runs begin; if it is changed, comparison will stop rather than silently compare against a different prediction.

## Run the replica

### Start the HTTP service

Docker must be installed. From the project directory:

```powershell
docker compose up --build -d
```

The host port is bound to `127.0.0.1:8000`, and the container is attached to a Docker network marked `internal`, with no outbound network access at runtime. The data folder is mounted locally so SQLite logs persist. The image build may need access to download its base image and Python packages; the running container does not have internet access.

The demo API is available at `http://127.0.0.1:8000/docs`. Its accounts and passwords are synthetic. For example, `acct-00000` uses the synthetic password `synthetic-password-acct-00000`; sensitive accounts use the synthetic MFA code `246810`. Do not reuse these patterns or this service for real accounts.

Stop the service with:

```powershell
docker compose down
```

### Produce the 108-cell replica observations

After calibration has generated `data/heldout_sessions.csv`, run:

```powershell
python -m replica.experiment
```

The runner replays held-out sessions resampled across the configured synthetic accounts, adds the selected synthetic attack traffic, and advances a virtual clock through the configured seven days. It uses the same `ReplicaService` enforcement logic in-process so time can be advanced quickly; it does not send the bulk experiment through Docker's HTTP endpoint. It batch-writes every request result to a timestamped SQLite database and writes the per-cell means to `data/observed.csv`.

Use `--runs 1` for a quick local check. The default comes from `simulation.replica_runs`; an override is recorded in `observed.csv` and accepted by the comparison step. The runner refuses to overwrite an existing SQLite log database.

### Synthetic traffic scripts

These scripts send requests to the Docker replica using synthetic passwords only. They are capped at 100 targets and have a hard-coded host guard: only plain HTTP to `localhost`, `127.0.0.1`, `::1`, or the `replica` container on port 8000 is accepted. The replica also exposes `POST /recover` for the synthetic self-service recovery rule. Its account-specific synthetic code is for demo/tests only, not a real reset mechanism.

```powershell
python -m attacks.brute_force --target-limit 10
python -m attacks.credential_stuffing --target-limit 10
python -m attacks.replay_traffic
```

The replay script requires the held-out CSV. The two attack scripts generate their candidate passwords and synthetic breached-credential list locally; they do not read external credential lists or accept arbitrary targets. API request logs are stored in `data/replica.sqlite3`.

## Compare predictions and observations

Generate predictions before replica runs, then generate observations. To create comparison outputs:

```powershell
python -m compare.run --observed .\data\observed.csv
```

The comparison command verifies `predictions.lock` before reading the results. It requires the same 108 policy/traffic cells in both files and uses the actual run counts recorded in the CSVs. It writes these files under `data/comparison/`:

- `cell_comparison.csv` — predicted and observed mean, signed/absolute error, confidence interval, and run counts per measure and cell.
- `metric_summary.csv` — MAE, RMSE, 95% interval coverage, and paired Wilcoxon signed-rank results per measure. Rate errors are reported in percentage points; the 5-point target applies to rate measures.
- `policy_rankings.csv` — policy scores and simulator/replica ranks. The score sums lockout and attack-success rates across the three traffic conditions; higher scores indicate more risk.
- `issue_flags.csv` — 108 items: one normal-traffic operational flag and two attack-scenario security flags per policy.
- `review_template.csv` — item IDs and five blank reviewer columns for manual review.
- `summary.json` — machine-readable summary including rank correlation and any optional review/SUS results.

Operational issues are lockout rates above 5%; security issues are attack-success rates above 1%. Both cutoffs, the `0.05` significance level, and the `0.80` Spearman target are in `compare/thresholds.yaml`.

To compare reviewer answers, fill the five reviewer columns in `review_template.csv` with `yes` or `no`, save it as a new CSV, then rerun:

```powershell
python -m compare.run --observed .\data\observed.csv --reviews .\data\review_answers.csv
```

The majority answer is yes when at least 3 of 5 reviewers select yes. Detection and false-alarm rates use observed replica issue flags as the reference. The exact McNemar test compares paired simulator and reviewer decisions and reports the discordant-item count.

For SUS, provide exactly 10 unique respondents with `respondent_id` and `q1` through `q10` columns. Each answer must be an integer from 1 to 5:

```powershell
python -m compare.run --observed .\data\observed.csv --sus .\data\sus_responses.csv
```

The standard SUS scoring method produces scores from 0 to 100. The report includes mean, sample standard deviation, 95% confidence interval, and comparison with the benchmark of 68.

## Streamlit app

### Start it from the desktop

Double-click **Policy Rehearsal** on your desktop. The first launch creates a private `.venv` for this project and installs the packages from `requirements.txt`; this setup step needs internet access. Later launches reuse that environment and open the app in your browser at `http://127.0.0.1:8501`.

Keep the terminal window open while using the app. Close that window to stop it. The app itself listens only on your own computer.

If you need to recreate the shortcut, create a Windows shortcut pointing to `Launch Policy Rehearsal.bat` in this project folder.

### Start it from PowerShell

```powershell
python -m streamlit run ui\app.py --server.address 127.0.0.1
```

Choose a threshold, lockout type and duration, MFA scope, recovery rule, and traffic condition, then run a prediction. The page uses the configured simulator run count and shows plain-language lockout, attack, challenge, recovery delay, and issue-flag results. If a matching row exists in `data/observed.csv`, it also charts predicted vs. replica rates.

The sidebar also lets you calibrate with an anonymized session-summary CSV or the built-in synthetic sample. The fitted values apply to predictions in the current app session. Select **Also save fitted settings and anonymized holdout for replica use** to explicitly update `simulator/settings.yaml` and create `data/heldout_sessions.csv`.
