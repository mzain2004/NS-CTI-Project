# AutoShield Deployment Steps

## 1. Deception Layer (Cowrie)
1. Move Host SSH to port 2222 (optional but recommended):
   - Edit `/etc/ssh/sshd_config` and change `Port 22` to `Port 2222`.
   - Run `systemctl restart ssh`.
2. Deploy Cowrie:
   - `cd cowrie`
   - `docker-compose up -d`
3. Port Forwarding (if not moved host SSH):
   - `iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222`

## 2. Middleware (FastAPI)
1. Set API Keys in `docker-compose.yml`.
2. Deploy:
   - `cd middleware`
   - `docker-compose up -d --build`

## 3. Wazuh Integration
1. Add the content of `wazuh-config/ossec_snippet.xml` to your Wazuh Manager's `/var/ossec/etc/ossec.conf`.
2. Deploy the block script to the host Wazuh Agent/Manager:
   - Copy `block-ip.sh` to `/var/ossec/active-response/bin/`.
   - `chmod 750 /var/ossec/active-response/bin/block-ip.sh`
   - `chown root:wazuh /var/ossec/active-response/bin/block-ip.sh`
3. Restart Wazuh Manager:
   - `docker-compose restart wazuh.manager` (or equivalent)

## 4. Wazuh Log Monitoring
Configure Wazuh Agent to read Cowrie JSON logs:
Add to `ossec.conf` on the agent monitoring Cowrie:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/path/to/autoshield/cowrie/cowrie-log/cowrie.json</location>
</localfile>
```
