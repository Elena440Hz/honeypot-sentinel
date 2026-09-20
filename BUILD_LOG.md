# Build Log — Sentinel Honeypot

A chronological, honest record of how this environment was built, including the
errors hit and how they were resolved. Written as I went, so it captures the
*real* process — not a sanitized tutorial. If you're reading this from my CV:
the value here is the troubleshooting, not the happy path.

Target architecture: an internet-facing Cowrie SSH honeypot on a cheap Azure VM,
locked down so a compromised box can't harm anyone, with logs destined for
PySpark analysis and a dashboard.

---

## 1. Requesting VM quota from Azure

**Problem.** My first `az vm create` failed:

```
Code: SkuNotAvailable
Message: The requested VM size ... 'Standard_B1s' is currently not available
in location 'westeurope'. ... Capacity Restrictions ...
```

Then, after switching sizes, a *different* failure:

```
Message: Operation could not be completed as it results in exceeding approved
standardBasv2Family Cores quota. ... Current Limit: 0 ...
```

**Why this happens.** Two distinct issues that look similar:
- `SkuNotAvailable` = Azure physically has no spare capacity of that exact VM
  size in that region right now. Nothing to do with my account.
- Quota `Current Limit: 0` = my *subscription* is approved for zero cores of
  that VM family in that region. New/low-usage subscriptions ship with 0 quota
  on many families until you request an increase. This is an account limit, not
  a capacity limit.

**How I resolved it.**
- Checked what was actually available rather than guessing:
  ```bash
  az vm list-skus --location westeurope --resource-type virtualMachines --all \
    --query "[?restrictions[0]==null && starts_with(name,'Standard_B')].name" -o table
  ```
- Learned to read the burstable size names: the letters encode RAM.
  `B2ts_v2` = 2 vCPU / 1 GiB (tiny), `B2ls_v2` = 2 vCPU / 4 GiB (low),
  `B2s_v2` = 2 vCPU / 8 GiB. The `a` variants (`B2als_v2`) are AMD-based.
- Because the `Basv2` family showed `Current Limit: 0`, the fix was a **quota
  increase request**: Portal → **Quotas** → **Compute** → filter region
  *West Europe* → find the family (e.g. *Standard BSv2 Family vCPUs*) →
  **Increase quota** → set new limit to 2–4 → Submit. For small B-series this
  is typically auto-approved within minutes.

**Lesson.** "Not available" and "quota exceeded" are different failures with
different fixes. Always inspect available SKUs and current quota before retrying
blindly.

---

## 2. Creating the VM (switched CLI → Portal)

**What I did.** After the CLI quota friction, I created the VM through the Azure
Portal GUI, which made the size/quota validation easier to see at the
*Review + create* step. Settings used:
- Resource group: `rg-honeypot` (dedicated, so teardown is one command later)
- Image: Ubuntu Server 22.04 LTS
- Authentication: SSH public key, "Generate new key pair" (Azure downloaded a
  `.pem` private key to my local Downloads folder)
- Username: `azureuser`
- Public IP: `51.124.24.161`

**Why a dedicated resource group.** Cleanup is then a single command
(`az group delete --name rg-honeypot --yes`) with no orphaned resources
quietly billing me.

**Connecting.**
```powershell
ssh -i "C:\Users\dimip\Downloads\<key>.pem" azureuser@51.124.24.161
```
(If Windows complains the key is "too open," restrict it with `icacls`.)

---

## 3. NSG rule conflict (port 2222)

**Problem.** Adding an inbound rule for my future admin SSH port failed:

```
(SecurityRuleConflict) Security rule default-allow-ssh conflicts with rule
allow-admin-ssh. Rules cannot have the same Priority and Direction.
```

**Why.** The Portal had already auto-created `default-allow-ssh` at priority
1000 for inbound port 22. My new rule also tried to use priority 1000. NSG rules
must have unique (priority, direction) pairs.

**How I resolved it.** Gave the new rule a different priority:
```powershell
az network nsg rule create -g rg-honeypot --nsg-name vm-honeypotNSG -n allow-admin-ssh `
  --priority 1010 --direction Inbound --access Allow --protocol Tcp `
  --destination-port-ranges 2222
```

**Lesson.** Azure evaluates NSG rules lowest-priority-number first; each rule
needs its own slot.

---

## 4. Near-lockout: the 2222 rule hadn't actually been created

**Problem.** After the plan moved real admin SSH to port 2222, a test connection
timed out:
```
ssh: connect to host 51.124.24.161 port 2222: Connection timed out
```

**Why.** Because of the earlier conflict (section 3), the port-2222 inbound rule
was never successfully created. A **timeout** (vs. "connection refused")
specifically indicates the NSG firewall is dropping packets before they reach
the VM — a strong signal the problem is the network rule, not the SSH service.

**How I resolved it.**
- Listed the NSG rules to confirm 2222 was genuinely missing:
  ```powershell
  az network nsg rule list -g rg-honeypot --nsg-name vm-honeypotNSG -o table
  ```
- Created the missing rule (priority 1010) and reconnected successfully.
- **Critical habit that saved me:** I never closed my original SSH session.
  Existing SSH connections survive config changes and even sshd restarts, so as
  long as one session stays open, you retain access while fixing networking.

**Lesson.** Timeout = network/NSG layer; "connection refused" = reached the host
but nothing is listening. The distinction tells you which layer to debug.

---

## 5. Cowrie install: the repo layout had changed

**Problem.** My original setup script did `cp etc/cowrie.cfg.dist etc/cowrie.cfg`
and failed:
```
cp: cannot stat 'etc/cowrie.cfg.dist': No such file or directory
```
Investigating, `etc/` contained only a `.gitignore` — the config templates
weren't where the old instructions expected.

**Why.** Cowrie has moved to a modern Python packaging layout (`pyproject.toml`,
a `src/` tree). The config templates now live at
`src/cowrie/data/etc/cowrie.cfg.dist`, and the recommended install is now a
**pip package** with a `cowrie init` command — not a clone-and-copy-config flow.
I confirmed this by reading the repo's own `INSTALL.rst`, which is the
authoritative, current source.

**How I resolved it.** Switched to the current supported install path:
```bash
# system build deps (Cowrie's crypto libs compile against these)
sudo apt-get install -y python3-pip python3-venv libssl-dev libffi-dev \
  build-essential libpython3-dev python3-minimal

# as the unprivileged 'cowrie' user
sudo -u cowrie bash
mkdir -p ~/honeypot && cd ~/honeypot
python3 -m venv cowrie-env && source cowrie-env/bin/activate
pip install --upgrade pip
pip install cowrie
cowrie init        # generates etc/cowrie.cfg from the bundled template
```

**Lesson.** When a tool won't behave, the project's own INSTALL doc beats any
third-party guide — upstream changes and stale tutorials are the #1 source of
"it doesn't work like the guide says."

---

## 6. Port collision: real SSH vs. fake SSH (both wanted 2222)

**Problem (caught before it bit).** The plan moved *real* admin SSH to 2222, but
Cowrie's *fake* SSH also defaults to 2222. Starting Cowrie would have collided
with the admin service.

**Why it matters.** Two services can't bind the same port. Worse, a collision on
the admin port could interfere with legitimate access.

**How I resolved it.** Pointed Cowrie's internal listener at **2223** instead:
```bash
nano etc/cowrie.cfg      # [ssh] section: listen_endpoints tcp:2222 -> tcp:2223
grep listen_endpoints etc/cowrie.cfg   # verify it now says 2223
```
Then the public bait port (22) is redirected to 2223 (section 7).

**Result.**
```bash
cowrie start
cowrie status      # -> cowrie is running (PID: ...)
```

---

## 7. Exposing the honeypot: iptables redirect 22 → 2223

**Why.** Attackers scan port 22. Cowrie listens on 2223 (an unprivileged port,
so it doesn't need root). A NAT redirect sends public :22 traffic to :2223.

**How.**
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2223
sudo iptables -t nat -L PREROUTING -n --line-numbers   # verify: tcp dpt:22 redir ports 2223
```

**Made persistent** (section 9) — the rule survives reboots via
`iptables-persistent`.

---

## 8. Egress lockdown (defense-in-depth)

**Why.** Cowrie is an *emulated* shell, so attackers shouldn't reach the real
OS — but as belt-and-suspenders, I restricted what the VM can send *outbound*.
Even in a worst-case escape, the box can't be weaponised to attack third parties,
mine crypto, or exfiltrate data. Done *after* install, because apt/pip/git all
need outbound access during setup.

**How (NSG outbound rules; lowest priority evaluated first).**
```powershell
# allow outbound web (occasional apt/pip updates)
az network nsg rule create -g rg-honeypot --nsg-name vm-honeypotNSG -n allow-out-web `
  --priority 2000 --direction Outbound --access Allow --protocol Tcp --destination-port-ranges 80 443
# allow outbound DNS
az network nsg rule create -g rg-honeypot --nsg-name vm-honeypotNSG -n allow-out-dns `
  --priority 2010 --direction Outbound --access Allow --protocol Udp --destination-port-ranges 53
# deny everything else outbound
az network nsg rule create -g rg-honeypot --nsg-name vm-honeypotNSG -n deny-out-all `
  --priority 4000 --direction Outbound --access Deny --protocol '*' --destination-port-ranges '*'
```
Admin SSH is inbound, so this outbound lockdown doesn't affect my access —
verified by reconnecting on port 2222 afterwards.

---

## 9. Reboot persistence: iptables + Cowrie systemd service

**Why.** Both the redirect and Cowrie were only running in memory. A reboot
would silently kill the honeypot (attacks would hit a closed port, no logs).

**iptables persistence.**
```bash
sudo apt-get install -y iptables-persistent   # "Save current IPv4 rules?" -> Yes
sudo netfilter-persistent save
sudo cat /etc/iptables/rules.v4 | grep 2223    # confirm the redirect is saved
```

**Cowrie systemd service — and a bug I hit.** My first unit file failed:
```
FileNotFoundError: [Errno 2] No such file or directory   (in os.execvp)
```
*Why.* Cowrie's `start` launcher execs `twistd`. Under systemd the service runs
with a **bare PATH** that doesn't include the virtualenv's `bin/`, so `twistd`
wasn't found. When I ran Cowrie by hand earlier it worked because the activated
venv had put that dir on PATH.

*Fix.* Add the venv to the service environment:
```ini
Environment=HOME=/home/cowrie
Environment=VIRTUAL_ENV=/home/cowrie/honeypot/cowrie-env
Environment=PATH=/home/cowrie/honeypot/cowrie-env/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
After `daemon-reload` + `restart`, the service came up **active** and Cowrie was
listening on 2223 again.

**A smaller gotcha along the way.** Running `cowrie stop` as
`sudo -u cowrie ... cowrie stop` from `/home/azureuser` failed with a
`PermissionError` on `var/run/cowrie.pid` — because Cowrie resolves its pidfile
*relative to the current directory*. Fix: `cd /home/cowrie/honeypot` first (the
systemd unit sets `WorkingDirectory`, so it's immune).

**Lesson.** systemd is a clean-room environment: no PATH, no venv, minimal env
vars. Anything your shell provided implicitly must be declared explicitly.

---

## Verification: self-test attack

Rather than wait for bots to find a brand-new IP, I attacked the honeypot from
my own machine to prove the full chain works:
```
ssh attacker-test@<public-ip>      # port 22, no key, any password
```
The log captured it end-to-end:
```json
{"eventid":"cowrie.login.success","username":"attacker-test",
 "password":"password123","message":"login attempt [...] succeeded", ...}
```
Bonus artifacts Cowrie records per connection (useful for later analysis):
`src_ip`, client version string, and a **hassh** fingerprint (a hash of the
client's SSH crypto capabilities — lets you cluster attacks by tool even when
IPs rotate).

Note: connecting to port 22 after the redirect triggered an SSH
"REMOTE HOST IDENTIFICATION HAS CHANGED" warning locally — expected, because
port 22 now presents Cowrie's host key instead of the real server's. Cleared
with `ssh-keygen -R <ip>`.

**Reboot test (proves persistence).** After `sudo reboot`, I confirmed both
survive: the systemd service showed `active (exited)` with a live `twistd`
process, and port 22 still redirected to Cowrie. Real admin access is separate:
port **2222**, key-only.

**The trap even caught its owner.** During the reboot test I connected to port
22 with a placeholder key path (so SSH fell back to password auth) and typed a
throwaway password — and landed in a shell prompted `azureuser@svr04`. That's
Cowrie's *fake* hostname, not my real `vm-honeypot`. I'd logged into my own
honeypot, exactly as an attacker would. Good reminder of how to tell them apart:
real = hostname `vm-honeypot` + port 2222 + key auth; fake = hostname `svr04` +
port 22 + any password "works".

---

## 10. Reading the catch, and a hardening decision

**The catch (one night).** `wc -l` on the log showed **17,713 events**: 2,156 login
attempts, **381 unique attacker IPs**, and **3,307 commands** run inside the fake
shell. A brand-new IP was found and hammered by botnets within hours.

**Something odd — and how I ran it down.** Counting destination ports in the log:
```bash
sudo grep -o '"dst_port":[0-9]*' .../cowrie.json | sort | uniq -c
#   2484 "dst_port":2223   <- the honeypot itself (expected)
#    103 "dst_port":80      <- ???
#      6 "dst_port":443     <- ???
```
Ports 80/443 weren't attacks *on* the honeypot — they were the *destinations
attackers tried to reach FROM inside the fake shell*. Checking the event types:
```bash
sudo grep -E '"dst_port":(80|443)' .../cowrie.json | grep -o '"eventid":"[^"]*"' | sort | uniq -c
#   cowrie.direct-tcpip.request / .data / .ja4 / .ja4h
```
These are **SSH tunneling / proxy-relay attempts** — bots trying to use the box
as an anonymizing proxy to attack *other* sites. The destinations confirmed it:
103 hits to `ip-who.com` (a "what's my exit IP?" proxy-validation service) and 6
to `8.8.8.8` (a connectivity check).

**Why it wasn't a breach.** `forwarding = true` (Cowrie's default) makes Cowrie
*accept and log* these tunnel requests — which is why the rich JA4 data was
captured — but `forward_tunnel = false` and `forward_redirect = false` mean it
never *actually relays* the traffic. Evidence backed this: a working open proxy
gets flooded with victim traffic; this got a handful of *test* probes and was
abandoned. Nothing left the box toward a victim.

**The decision.** Because the egress NSG *allows* outbound 80/443 (for updates),
Cowrie's `forward_tunnel = false` was the *only* guard for those two ports. To
remove even the theoretical risk, I disabled forwarding entirely — Cowrie now
*rejects* the tunnel channels outright:
```bash
sudo sed -i 's/^forwarding = true/forwarding = false/' /home/cowrie/honeypot/etc/cowrie.cfg
sudo systemctl restart cowrie
```
Already-captured proxy/JA4 data stays in the log; only *new* tunnel channels are
refused going forward.

**Lesson.** Audit your own infrastructure like an attacker would. The one setting
worth changing wasn't in a guide — it surfaced from reading the actual traffic.
`ja4`/`ja4h` are modern TLS/HTTP client fingerprints — useful later for
clustering attackers by tool even across changing IPs.

---

## 11. Shipping logs to Azure Blob Storage

**Why.** PySpark runs on Databricks — a separate machine that can't read the VM's
filesystem. So the log has to move to neutral ground both sides can reach: cloud
object storage. This is the **separation of collection from analysis** pattern —
the collector (VM) and the analyzer (Spark) are linked by a storage layer.

```
[VM: cowrie.json]  --upload over HTTPS 443-->  [Azure Blob: raw-logs]  --read-->  [PySpark]
```
(This is *why* egress allows 443 — the pieces connect.)

**Storage account — blocked by governance policy.** `az storage account create`
was denied:
```
(RequestDisallowedByPolicy) ... "Deny Unencrypted HTTPS Storage Acts" ...
supportsHttpsTrafficOnly NotEquals true
```
The subscription enforces a policy that every storage account must be HTTPS-only.
Fix: add the flag that sets it (found via `az storage account create --help`,
searching for `https`):
```powershell
az storage account create --name sthoneypotkp2026 --resource-group rg-honeypot `
  --location westeurope --sku Standard_LRS --kind StorageV2 --https-only true
```
**Lesson.** `--help` + search for the error's keyword is the universal move for
"the platform rejected my request." Also: meeting an Azure Policy from the *other*
side of the audit desk is good perspective for the day job.

**Container.** A `raw-logs` container, private (no anonymous access):
```powershell
az storage container create --account-name sthoneypotkp2026 --name raw-logs --public-access off
```
Concept: **account** = infra/billing/security boundary (the building); **container**
= an access-scoped partition (a room); **blob** = a file. One account can hold
`raw-logs` / `processed` / `gold` rooms — mini medallion architecture.

**Auth.** The data plane needs its own credential — either a **shared key**
(connection string) or **Azure AD RBAC** (`--auth-mode login`). For a script,
the connection string is pragmatic; it's a master secret, so it lives in a
git-ignored `.env`, never in code.

**`ship_logs.py`.** Loads the secret from `.env` (`python-dotenv`), connects with
`BlobServiceClient.from_connection_string(...)`, and uploads the file to a
**dated** blob name (`cowrie-YYYY-MM-DD.json`) so each ship builds history. It
uploads the log **raw and untouched** — the "bronze" layer; all parsing/filtering
happens downstream in PySpark, so no field is ever lost early.

**Bug — the `.env` had no variable name.** First run:
```
KeyError: 'AZURE_STORAGE_CONNECTION_STRING'
```
A safe peek (`head -c 35 ~/.env`) showed the file started with
`DefaultEndpointsProtocol=` — I'd pasted the raw connection string with no
`NAME=` in front, so dotenv never defined the variable the script asked for. Fix:
wrap it as `AZURE_STORAGE_CONNECTION_STRING="...full string..."` (quoted, because
the value is full of `=` and `;`). Also pinned `load_dotenv(os.path.expanduser("~/.env"))`
to an explicit path to remove any find-the-file ambiguity.

**Result.** `cowrie-2026-07-20.json` now sits in the `raw-logs` container —
17K events of real attack data in the cloud, ready for PySpark.

**Lesson.** A `.env` file is `NAME=value` pairs. Pasting just the value gives you
a variable named after the *value's* first token — a silent, confusing failure.

---

## 12. Downloading the log for analysis (control plane vs data plane)

**Why download at all.** Databricks Free Edition runs on Databricks' *own* cloud
(AWS-hosted), not inside Azure — so it can't cheaply read the Azure Blob "live."
A live cross-cloud feed would need an Azure **service principal** wired to a Unity
Catalog **external location**. Pragmatic path for now: pull the raw blob back to
the laptop, then upload it into a Databricks **Volume**. The live Blob→Spark
pipeline is scoped as a v2 upgrade (see Open items).

**The auth workaround — why `--account-key` instead of my own identity.**
Downloading a blob is a **data-plane** action, and that's a *different* permission
set from the **control plane**:

- **Control plane** = the account object itself — create it, read its config.
  I'm subscription **Owner**, so this is mine.
- **Data plane** = the bytes *inside* the blobs. This needs a **Storage Blob Data**
  role — which **Owner does not include.**

So `--auth-mode login` (authenticate as my Azure AD identity) would fail with
`AuthorizationPermissionMismatch` (403), because no *Storage Blob Data Reader* role
is assigned to me. Instead I authenticated with the **account key** — the account's
master credential, which any control-plane Owner can read:

```powershell
$KEY = az storage account keys list --resource-group rg-honeypot `
  --account-name sthoneypotkp2026 --query "[0].value" -o tsv

az storage blob download --account-name sthoneypotkp2026 --account-key $KEY `
  --container-name raw-logs --name "cowrie-2026-07-20.json" `
  --file "$HOME\Downloads\cowrie-2026-07-20.json"
```

**Lesson.** In Azure Storage, *"I own the account" ≠ "I can read the data."* RBAC
deliberately splits **control-plane** (management) from **data-plane** (the bytes),
so you can — for example — let an app read blobs without giving it power to
reconfigure or delete the account. Two clean fixes exist: assign myself **Storage
Blob Data Reader** (keyless, Azure AD, the modern preference), or use the **account
key** (fast, but a reusable master secret). I used the key here for speed; the role
assignment is the better long-term habit.

---

## 13. First PySpark analysis on Databricks Free Edition

**Setup.** Signed up for Databricks Free Edition (serverless Spark, no card).
Uploaded `cowrie-2026-07-20.json` into a Unity Catalog **Volume**
(`/Volumes/workspace/default/honeypot/`) — Free Edition is cross-cloud to Azure,
so a local Volume beats fighting a live Blob connection for now (see §12). Loaded
it in a notebook:

```python
path = "/Volumes/workspace/default/honeypot/cowrie-2026-07-20.json"
df = spark.read.json(path)            # JSON-lines: one line -> one row
df.createOrReplaceTempView("events")  # so SQL cells can see it too
```

`df.count()` → **18,648 events** (the log grew past the first 17,713 count before
it was shipped). `printSchema()` showed a **wide union schema**: Spark unions every
key it ever saw, so any one row only fills the fields its `eventid` uses (a login
row fills `username`/`password`; a command row fills `input`). You slice by
filtering on `eventid`.

**Key concept — DataFrame API vs SQL is a *readability* choice, not a performance
one.** Both compile through Spark's **Catalyst** optimizer to the *same* physical
plan (`.explain()` proves it). Every analysis below was written both ways and ran
identically; an observed "SQL is faster" was just warm-cache / JVM-warmup noise.

**Findings:**

- **Top source IPs.** One host — `45.153.34.181` — sent **6,086 of 18,648** events
  (~33%); a handful of hosts make most of the noise. Three IPs shared the
  `92.118.39.0/24` block → one operator spread across a subnet to dodge per-IP
  rate limits. (`GROUP BY src_ip`.)
- **Top credentials.** Every top username was `root` or `admin` (attackers only
  want privilege). Passwords were classic weak defaults (`123456`, `admin`,
  `1q2w3e4r`, `passw0rd`) from **Mirai-style wordlists**. Counts were small (≤33)
  — the signature of a **dictionary attack**: breadth over repetition.
  (`WHERE eventid LIKE 'cowrie.login%'`.)
- **Top commands — a full kill chain, captured.** Three phases: (1) **recon /
  fingerprinting** (`uname -s -v -n -r -m`; a huge one-liner probing CPU arch for
  `x86_64`/`aarch64`/`armv7l` to pick the right payload); (2) **honeypot / sandbox
  testing** (writing + `chmod` + exec of a `filter` script to check for a real,
  unrestricted shell); (3) the **payload**, run exactly once:
  ```
  chmod +x ./.1988208513807693888/xinetd; nohup ./.1988208513807693888/xinetd &
  ```
  A hidden `.`-directory (T1564.001), a binary **masquerading** as the `xinetd`
  daemon (T1036), run **detached** for persistence (T1059). Likely a cryptominer /
  DDoS-bot loader. **This is the headline capture.** On a real host it would have
  been game-over — here Cowrie faked every response so **nothing executed**, and
  the egress lockdown (§8) would have blocked the loader's C2 anyway. Full attack
  chain recorded at zero risk.
- **Attacks over time (hourly).** Clear spikes (~06:00 and ~11:00). *Times are UTC*
  — Cowrie logs UTC and Spark's default session timezone is UTC; Greek summer time
  is UTC+3, so the 06:00 spike is ~09:00 local. Drilling in confirmed that bulge is
  almost entirely *one* host: `45.153.34.181` fired its whole 6,086-event run inside
  two UTC hours (06:00–08:00) — ~95% of the spike — so it's a **campaign burst, not
  a timezone signal.** **Open hypothesis for the GeoIP
  stage:** do source countries cluster in timezones near the spike hours, or (more
  likely for automated botnets) is timing just *when a campaign's scan wave fired*,
  independent of operator geography? The single dominant IP suggests the latter.
  (`GROUP BY date_trunc('hour', to_timestamp(timestamp))`.)

**MITRE ATT&CK observed:** T1082 (System Information Discovery), T1497
(Virtualization/Sandbox Evasion), T1564.001 (Hidden Files/Directories), T1036
(Masquerading), T1059 (Command & Scripting Interpreter / execution).

---

## 14. GeoIP enrichment + the Streamlit dashboard

**The serving pipeline.** Three stages, deliberately separated so each is testable:
```
raw log -> build_gold.py -> gold CSVs -> enrich_geoip.py -> gold_ips_geo.csv -> app.py
(10 MB)    (aggregate)     (a few KB)    (+country/ISP)                        (dashboard)
```
`build_gold.py` is the medallion **gold layer**, right-sized: at 10 MB pandas does
in a second what Spark did in the notebook, and the dashboard then reads only tiny
pre-aggregated files instead of re-parsing the raw log on every page load. At
production scale this same step runs in Spark and writes to Blob — the *shape* is
identical, only the engine changes.

**GeoIP — batch, not one-by-one.** The first version looked up each IP separately
with a 1.4 s sleep for the rate limit: 386 IPs ≈ **9 minutes**. Switched to
ip-api.com's `/batch` endpoint (100 IPs per POST, results returned in input order):
**4 requests, seconds.** Same instinct as replacing 386 single-row lookups with one
`JOIN`. Also pulled **ISP + ASN**, which turned out to be the most interesting field
of all. All 386 IPs resolved, 0 failures. *(Production alternative: a local MaxMind
GeoLite2 `.mmdb` — offline, no rate limit, fully reproducible.)*

**Bug — schema mismatch between stages.** `enrich_geoip.py` died with
`KeyError: 'ip'`: `build_gold.py` had written Cowrie's native column name `src_ip`,
while the enrichment expected a clean `ip`. Fixed by renaming at the gold boundary
(`.rename(columns={"src_ip": "ip"})`). **Lesson:** the gold layer is a *published
contract* — that's exactly where raw source names should be normalised, so
downstream consumers never inherit the source's vocabulary.

**Results — and the bet.** A standing wager from §13: would source countries cluster
within ±3 h of Greek time?

| Country | Attacks |
|---|---|
| The Netherlands | 10,391 |
| United States | 2,738 |
| China | 883 |
| Pakistan | 802 |
| India | 740 |
| Vietnam | 510 |

**Bet lost, but the *reason* is the finding.** The US (UTC−5), China (+5) and Vietnam
(+4) are all far outside ±3 h. And the winner is absurd on its face: nobody is
attacking from a Dutch bedroom. Look at *who owns* the top networks —
**"TechTies Inc."**, **"Unmanaged LTD"**, **"Storm Industries LLC"**: abuse-tolerant
/ bulletproof VPS hosting. The clincher: **`AS47890 "Unmanaged LTD"` appears under
BOTH the Netherlands and the United States** — one operator, two flags.

> **Conclusion: an attacker's GeoIP country is where the rented server sits, not
> where the human is.** You cannot infer an operator's timezone (or nationality)
> from a datacenter's location. Combined with §13's finding that the 06:00 spike was
> ~95% one host's campaign burst, both "geographic" signals dissolved under scrutiny.
> The bet was unwinnable by construction — and proving *that* is worth more than
> winning it. Useful counterweight to threat-intel reporting that maps attacks to
> countries as if that named the adversary.

**Dashboard design decisions** (`dashboard/app.py`, Streamlit + Plotly):
- Headline figures are **stat tiles, not charts** — a single number's job is to be
  read, not plotted.
- The map uses **bubbles sized by volume, not a choropleth**: the top source is the
  physically tiny Netherlands, which a fill-by-country map would visually bury while
  over-weighting large, quiet landmasses.
- Every panel is a **single series → one accent hue**, sorted bars, direct value
  labels. No rainbow, no dual-axis.
- The dashboard reads **only the gold layer** — it never touches the raw log, so it
  stays fast and could be deployed with no honeypot running at all.
- A caption states the hosting-vs-operator caveat directly on the map, so the chart
  can't be misread on its own.

---

## Cost & safety summary

- VM: burstable v2 B-series, ~€8–14/month depending on size. Attack *volume*
  does not affect cost — inbound traffic is free and a login attempt is just a
  log line. The fixed VM uptime is the only real cost.
- Budget alerts set at €20 and €40 as a safety net (never expected to fire).
- Teardown when done: `az group delete --name rg-honeypot --yes` removes VM,
  disk, IP, and NSG in one command.

---

## Open items (next sessions)

- [x] Make the iptables redirect persistent across reboots.
- [x] Cowrie auto-starts on boot via systemd.
- [x] Disabled direct-tcpip forwarding after auditing the captured traffic.
- [x] Ship `cowrie.json` to Azure Blob Storage (`ship_logs.py`) — one-off done.
- [ ] Schedule `ship_logs.py` to run daily (cron) with an automatic fresh copy.
- [x] PySpark analysis on Databricks Free Edition — top IPs, credentials, commands,
  hourly trend (see §13).
- [x] GeoIP enrichment + Streamlit dashboard (§14) — bet settled.
- [ ] Live cross-cloud Blob → Databricks feed (Azure service principal + Unity
  Catalog external location) — the "v2 upgrade" replacing the manual download (§12).
- [ ] Deploy the dashboard publicly (Streamlit Community Cloud) for a CV link.
- [ ] Write the README's "What I learned" section in my own words.
- [ ] Add a "Top attacker IPs" panel to the dashboard (solo exercise).
- [ ] Closed-book rebuild of the honeypot from scratch to prove the steps stuck.

---

## Teardown (2026-07-26)

Deleted the whole `rg-honeypot` resource group after ~1 week — **€3.95 total**.
Everything lived in one dedicated group precisely so cleanup was one command:

```powershell
az group delete --name rg-honeypot --yes --no-wait
```

Nothing of value was lost, because the pipeline had already been designed to
survive it: the raw log was copied locally, and the small **gold layer is
committed to the repo**, so the dashboard still runs with no Azure resources and
no honeypot alive. That separation — collection is disposable, analysis is
portable — is the point.

**To rebuild:** `docs/SETUP.md` is the runbook, `infra/setup_cowrie.sh` the script.
A fresh VM gets a new public IP; nothing else changes.
