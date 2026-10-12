# Deploying to Render

This folder is the server root. Push it to a GitHub repo and connect that repo on Render.

## 1. Push to GitHub

From the `server/` folder:

```powershell
git init
git add .
git commit -m "Initial server"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

The `.gitignore` keeps `data/`, `secret.key`, `keys.txt`, and credential files out of the repo. Nothing sensitive is pushed.

## 2. Create the Render service

Option A — Blueprint (uses the `render.yaml` in this folder):

1. Go to <https://dashboard.render.com/blueprints> and click **New Blueprint**.
2. Pick your GitHub repo. Render reads `render.yaml` and creates the service + 1 GB disk.
3. Starter plan is $7/month and gets you the persistent disk — required so the DB and signing key survive deploys.

Option B — Manual:

1. **New +** → **Web Service** → connect the repo.
2. Runtime: Python 3. Build: `pip install -r requirements.txt`. Start: `python run.py`.
3. Add a disk under **Settings → Disks**: mount path `/var/data`, size 1 GB.
4. Add env vars under **Settings → Environment**:
   - `LICENSE_HOST = 0.0.0.0`
   - `LICENSE_DATA_DIR = /var/data`
   - `PYTHON_VERSION = 3.12.3`

Free plan works but has no disk — the SQLite DB and signing key get wiped on every redeploy, so every deploy means new admin creds and a new server pubkey (which breaks already-shipped loaders). Use starter+ for anything real.

## 3. First boot

Watch the deploy log. On the first run the server prints:

```
========================================
License server first-run admin credentials
  username: xxxxxxxx
  password: xxxxxxxxxxxxxxxx
========================================
```

Copy those immediately — they're also written to `/var/data/FIRST_RUN_CREDENTIALS.txt` on the disk. Open `https://<your-service>.onrender.com/admin` and sign in.

## 4. Update the loader's embedded pubkey hash

The server generates its own signing key on first boot. The loader has `SERVER_PUBKEY_SHA256_HEX` embedded in `KeyAuth.cpp` — it anchors trust in the server. You need to update this once per fresh server deploy.

1. Download the pubkey:
   ```
   curl https://<your-service>.onrender.com/api/pubkey
   ```
   You get 128 hex characters (uncompressed P-256 X||Y).
2. Compute its SHA-256:
   ```powershell
   $pub = (curl.exe https://<your-service>.onrender.com/api/pubkey)
   $bytes = [byte[]]::new($pub.Length / 2)
   for ($i = 0; $i -lt $bytes.Length; $i++) {
       $bytes[$i] = [Convert]::ToByte($pub.Substring($i*2, 2), 16)
   }
   $sha = [System.Security.Cryptography.SHA256]::Create()
   -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
   ```
3. Paste the 64-char hex into `KeyAuth.cpp` → `SERVER_PUBKEY_SHA256_HEX`.
4. Also update `kServerBaseUrl` in `KeyAuth.cpp` from `http://127.0.0.1:8787` to your Render URL (`https://<your-service>.onrender.com`).
5. Rebuild `astre.exe` and ship.

## 5. Keys backup

Every generated key is appended to `/var/data/keys.txt` on the disk (survives deploys as long as you keep the disk). The dashboard also has a **Download .txt** button on the Keys page that generates a full snapshot from the DB on demand — grab it periodically as an off-server backup.
