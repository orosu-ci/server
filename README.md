# Órosu

> From Japanese 降ろす (órosu) — to unload / offload.

A secure CI/CD delivery tool designed to replace ad-hoc SSH/SCP steps in GitHub Actions and other CI workflows.

Instead of configuring SSH keys, users, file paths, and brittle deployment scripts in every pipeline, you install *
*orosu-server** once on your target machine and let CI push deployment jobs to it through secure WebSocket connections.

---

## The Problem

CI systems excel at building but struggle with delivery:

- **SSH keys** spread across multiple pipelines and repositories
- **SFTP/rsync** scripts copy-pasted everywhere, hard to maintain
- **Fragile permissions** and hardcoded paths breaking deployments
- **Production servers** directly exposed to CI runners
- **Secret sprawl** making credential rotation a nightmare

---

## The Solution

Orosu provides a controlled execution boundary between CI and production:

1. **CI builds** your application (binary, container, assets, etc.)
2. **CI triggers** an orosu job via WebSocket with optional file attachments
3. **orosu-server** authenticates the request using Ed25519 cryptography
4. **orosu-server** executes a **predefined script** locally on the target machine
5. The script handles deployment using the attached files and arguments

**No direct SSH. No credential juggling. No pipeline-specific hacks.**

---

## Quick Start

### 1. Install orosu-server

On your target deployment machine (Debian/Ubuntu):
```bash
curl -fsSL https://packages.nerdy.pro/NerdyPro.gpg | sudo gpg --dearmor -o /usr/share/keyrings/nerdy-pro.gpg
echo "deb [signed-by=/usr/share/keyrings/nerdy-pro.gpg] https://packages.nerdy.pro/ stable main" | sudo tee /etc/apt/sources.list.d/nerdy-pro.list
sudo apt update
sudo apt install orosu
```
This will add the nerdy-pro repository which hosts the binaries and install the `orosu-server` and `orosu-keygen` package.

### 2. Generate a key pair
Navigate to `/etc/orosu` directory and execute the keygen command
```bash
cd /etc/orosu
orosu-keygen --name my-ci-client --private-key-output my-ci-client.key --public-key-output my-ci-client.pub 
```
This will output:
- Public key (to be added to server config)
- Private key (to be used in CI secrets)

### 3. Configure orosu-server
Navigate to `/etc/orosu` directory and edit the `orosu-server.toml` file.
```yaml
listen:
    tcp: "127.0.0.1:8081"
```
This line will make the server listen on TCP port 8081.

Note that you may not want to expose the server to the public internet. In this case, you need to configure a reverse proxy.

```
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    ... your current nginx configuration ...
    
    location /deploy/ {

        proxy_pass http://127.0.0.1:8081/;

        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;

        proxy_buffering off;
    }
}
```
The above configuration will proxy all requests to `/deploy/` to the server and make the `orosu-server` available on the `wss://your-domain/deploy/` URL.

Next, scroll down to the `clients` section and add your client's public key:
```yaml
clients:
  - name: my-ci-client
    secret_file: /etc/orosu/my-ci-client.pub
```

### 4. Define a script
Create a script file `test.sh` in `/etc/orosu/scripts` directory.
```bash
#!/bin/bash

echo "Hello, $1!"
```

Then add the following line to the `orosu-server.toml` file in the `scripts` section of a newly defined client:
```yaml
clients:
  - name: my-ci-client
    secret_file: /etc/orosu/my-ci-client.pub
    scripts:
      - name: test-script
        command:
          - "bash"
          - "/etc/orosu/scripts/test.sh"
```

### 5. Test run
Open the secrets of your repository and add the private key file as a secret named `OROSU_CLIENT_KEY` and your server address as `OROSU_SERVER_URL`.
Next you need to go to your CI pipeline and add a step to trigger the job.
```yaml
- name: Remotely execute a script
  uses: orosu-ci/orosu@v0
  with:
    address: ${{ secrets.OROSU_SERVER_URL }}
    script: test-script
    key: ${{ secrets.OROSU_CLIENT_KEY }}
    arguments: "from CI pipeline"
```

As soon as you will trigger the job, the server will execute the script and print `Hello, from CI pipeline!` to the log.