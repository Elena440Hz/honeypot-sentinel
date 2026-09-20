# Setup Runbook — from zero to first captured attack

Follow these phases in order. Each step is copy-paste. You need the Azure CLI
installed (`az`) and an Azure subscription (your **personal** one, not work).

> **Is this safe?** Yes. Cowrie is a *fake* emulated shell — attackers never
> reach the real OS, so they can't mine crypto or pivot. Attacks are just log
> lines and cost nothing. The only cost is the VM (~€8–9/month for a B1s).

---

## Phase 0 — One-time safety net: the budget alert (Portal, 2 min)

Do this **first**, before anything exists to cost money.

1. Azure Portal → search **Cost Management + Billing** → **Budgets** → **+ Add**.
2. Scope: your subscription. Amount: **50 EUR/month**.
3. Add alert thresholds at **40%** (€20) and **80%** (€40), email = your email.
4. Save. Now you literally cannot be surprised by a bill.

---

## Phase 1 — Create the VM (CLI, 5 min)

Open a terminal and set some variables (change nothing except maybe LOCATION):

```bash
az login

RG="rg-honeypot"
LOCATION="westeurope"
VM="vm-honeypot"
ADMIN="azureuser"
```

Create a **dedicated resource group** (so cleanup later is ONE command):

```bash
az group create --name "$RG" --location "$LOCATION"
```

Create the VM — small, cheap Ubuntu, auto-generates an SSH key for you:

```bash
az vm create \
  --resource-group "$RG" \
  --name "$VM" \
  --image Ubuntu2204 \
  --size Standard_B2ts_v2 \
  --admin-username "$ADMIN" \
  --generate-ssh-keys \
  --public-ip-sku Standard
```

> **If you hit `SkuNotAvailable` / "Capacity Restrictions":** that region is
> temporarily out of that size for your subscription. Find one that IS available:
> ```bash
> az vm list-skus --location "$LOCATION" --resource-type virtualMachines --all \
>   --query "[?restrictions[0]==null && starts_with(name,'Standard_B')].name" -o table
> ```
> `Standard_B2ts_v2` (2 vCPU / 1 GiB, ~€8/mo) is the cheap default that's widely
> available. Swap `--size` accordingly, or try another region (northeurope,
> swedencentral, germanywestcentral).

When it finishes, grab the public IP (you'll need it):

```bash
az vm show -d -g "$RG" -n "$VM" --query publicIps -o tsv
```

`az vm create` already opened inbound port 22 — that becomes the honeypot bait.
Now also allow your *future* admin port 2222:

```bash
NSG="${VM}NSG"
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n allow-admin-ssh \
  --priority 1000 --direction Inbound --access Allow --protocol Tcp \
  --destination-port-ranges 2222
```

---

## Phase 2 — Install Cowrie (10 min)

Connect to the VM (SSH is still on 22 at this point):

```bash
ssh azureuser@<PUBLIC-IP>
```

Copy the `infra/setup_cowrie.sh` script from this repo onto the VM and run it.
Easiest way — paste its contents into a file and execute:

```bash
nano setup_cowrie.sh      # paste the file contents, Ctrl+O to save, Ctrl+X to exit
chmod +x setup_cowrie.sh
./setup_cowrie.sh
```

The script does the whole install end-to-end: moves real SSH to 2222, installs
Cowrie via pip, sets Cowrie's fake SSH to 2223, adds the port-22 -> 2223
redirect, makes that redirect reboot-persistent, and installs a systemd service
so Cowrie auto-starts on boot.

**Important:** it moves your real SSH to port **2222** near the start. Open a
SECOND terminal and confirm the new port works BEFORE closing your current one:

```bash
ssh -i <key>.pem -p 2222 azureuser@<PUBLIC-IP>
```

> The NSG must allow inbound **2222** (admin) in addition to **22** (bait). If
> `ssh -p 2222` times out, the NSG rule is missing — see the near-lockout story
> in docs/BUILD_LOG.md section 4.

---

## Phase 3 — Watch it work (the fun part)

On the VM, tail the honeypot log (note the path — Cowrie's pip layout puts state
under `~/honeypot`):

```bash
sudo tail -f /home/cowrie/honeypot/var/log/cowrie/cowrie.json
```

To prove it works immediately without waiting for bots, attack it yourself from
another machine: `ssh someuser@<PUBLIC-IP>` (port 22, no key), enter any
password, and watch the `cowrie.login` event appear in the log.

Within an hour (often minutes) you'll see real login attempts from real
botnets. **Screenshot the first one** — it's your motivation and your first
README image.

---

## Phase 4 — Lock down egress (do this AFTER Cowrie installed OK)

This is defense-in-depth + your best CV story. It blocks the VM from making
arbitrary outbound connections, while still allowing OS updates (DNS/HTTP/HTTPS).

```bash
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n allow-out-web \
  --priority 1000 --direction Outbound --access Allow --protocol Tcp \
  --destination-port-ranges 80 443
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n allow-out-dns \
  --priority 1010 --direction Outbound --access Allow --protocol Udp \
  --destination-port-ranges 53
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n deny-out-all \
  --priority 4000 --direction Outbound --access Deny --protocol '*' \
  --destination-port-ranges '*'
```

> Write a paragraph in the README about *why* you did this. "I restricted
> outbound egress so a compromised honeypot couldn't be weaponised against
> third parties" is exactly the security-minded thinking interviewers want.

---

## Teardown — when you want to stop paying (ONE command)

Because everything lives in one resource group:

```bash
az group delete --name rg-honeypot --yes
```

Everything — VM, disk, IP, NSG — gone. This is *why* we used a dedicated group.
