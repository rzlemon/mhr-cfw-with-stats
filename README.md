# MHR-CFW - MasterHttpRelay + Cloudflare Worker

[![GitHub](https://img.shields.io/badge/GitHub-MasterHttpRelayVPN-blue?logo=github)](https://github.com/denuitt1/mhr-cfw)


| [English](README.md) | [Persian](README_FA.md) |
| :---: | :---: |

## Disclaimer

`mhr-cfw` is provided for educational, testing, and research purposes only.

- **Provided without warranty:** This software is provided "AS IS", without express or implied warranty, including merchantability, fitness for a particular purpose, and non-infringement.
- **Limitation of liability:** The developers and contributors are not responsible for any direct, indirect, incidental, consequential, or other damages resulting from the use of this project or the inability to use it.
- **User responsibility:** Running this project outside controlled test environments may affect networks, accounts, proxies, certificates, or connected systems. You are solely responsible for installation, configuration, and use.
- **Legal compliance:** You are responsible for complying with all local, national, and international laws and regulations before using this software.
- **Google services compliance:** If you use Google Apps Script or other Google services with this project, you are responsible for complying with Google's Terms of Service, acceptable use rules, quotas, and platform policies. Misuse may lead to suspension or termination of your Google account or deployments.
- **License terms:** Use, copying, distribution, and modification of this software are governed by the repository license. Any use outside those terms is prohibited.

---

## How It Works

```
Client -> Local Proxy -> Google/CDN front -> GoogleAppsScript (GAS) Relay -> Cloudflare Worker -> Target website
             |
             +-> shows www.google.com to the network DPI filter
```
In normal use, the browser sends traffic to the proxy running on your computer.
The proxy sends that traffic through Google-facing infrastructure so the network only sees an allowed domain such as `www.google.com`.
Your deployed relay then fetches the real website through cloudflare worker and sends the response back through the same path.

This means the filter sees normal-looking Google traffic, while the actual destination stays hidden inside the relay request.

--- 

## How to Use

### 1 - Download project and extract 

```bash
git clone https://github.com/denuitt1/mhr-cfw.git
cd mhr-cfw
pip install -r requirements.txt
```
> **Can't reach PyPI directly?** Use this mirror instead:
> ```bash
> pip install -r requirements.txt -i https://mirror-pypi.runflare.com/simple/ --trusted-host mirror-pypi.runflare.com
> ```


### 2 - Set Up the Cloudflare Worker (worker.js)

1. Open [Cloudflare Dashboard](https://dash.cloudflare.com/) and sign in with your Cloudflare account.
2. From the sidebar, navigate to **Compute > Workers & Pages**
3. Click **Create Application**, Choose **Start with Hello World** and click on **Deploy**
4. Click on **Edit code** and **Delete** all the default code in the editor.
5. Open the [`worker.js`](script/worker.js) file from this project (under `script/`), **copy everything**, and paste it into the Apps Script editor.
6. **Important:** Change the worker on this line to the worker you created:
   ```javascript
   const WORKER_URL = "myworker.workers.dev";
   ```
7. Click **Deploy**.

### 3 - Set Up the Google Relay (Code.gs)

1. Open [Google Apps Script](https://script.google.com/) and sign in with your Google account.
2. Click **New project**.
3. **Delete** all the default code in the editor.
4. Open the [`Code.gs`](script/Code.gs) file from this project (under `script/`), **copy everything**, and paste it into the Apps Script editor.
5. **Important:** Change the password on this line to something only you know, also replace the worker url with your cloudflare worker:
   ```javascript
   const AUTH_KEY = "your-secret-password-here";
   const WORKER_URL "https://myworker.workers.dev";
   ```
6. Click **Deploy** → **New deployment**.
7. Choose **Web app** as the type.
8. Set:
   - **Execute as:** Me
   - **Who has access:** Anyone
9. Click **Deploy**.
10. **Copy the Deployment ID** (it looks like a long random string). You'll need it in the next step.

> ⚠️ Remember the password you set in step 3. You'll use the same password in the config file below.

### 4 - Run

Click on the `run.bat` file (on windows) or `run.sh` file (on linux) to start the relay.

If you're running for the first time it will prompt a setup wizard where you have to enter the AUTH_KEY and Google Apps Script Deployment ID.
You should see a message saying the HTTP proxy is running on `127.0.0.1:8085`

You can use [FoxyProxy](https://getfoxyproxy.org/) [Chrome Extension](https://chromewebstore.google.com/detail/foxyproxy/gcknhkkoolaabfmlnjonogaaifnjlfnp?hl=en) or [Firefox Extension](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) to use this proxy in your browser.

### 5 - Test your connection

Open [ipleak.net](https://ipleak.net) in your browser, you should see your ip address set as cloudflare's.

<img width="1454" height="869" alt="image" src="https://github.com/user-attachments/assets/dfd3316d-69b6-4b0e-b564-fdb055dbdafd" />
