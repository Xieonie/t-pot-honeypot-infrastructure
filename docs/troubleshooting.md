# T-Pot Honeypot Infrastructure Troubleshooting Guide 🔧

This guide provides solutions for common issues encountered during T-Pot honeypot deployment and operation.

## 📋 Table of Contents

- [Network Connectivity Issues](#network-connectivity-issues)
- [VM Creation and Configuration](#vm-creation-and-configuration)
- [OPNsense Firewall Issues](#opnsense-firewall-issues)
- [T-Pot Installation Problems](#t-pot-installation-problems)
- [Performance Issues](#performance-issues)
- [Security and Access Problems](#security-and-access-problems)
- [Monitoring and Logging Issues](#monitoring-and-logging-issues)
- [Common Error Messages](#common-error-messages)

## Network Connectivity Issues

### Problem: T-Pot VM cannot reach the internet

**Symptoms:**
- T-Pot installation fails during package download
- `ping 8.8.8.8` fails from T-Pot VM
- DNS resolution not working

**Solutions:**

1. **Check OPNsense LAN interface configuration:**
   ```bash
   # From OPNsense console
   # Option 2) Set interface IP address
   # Verify LAN interface has correct IP: 10.0.100.1/24
   ```

2. **Verify DHCP server on OPNsense:**
   ```bash
   # OPNsense Web Interface → Services → DHCPv4 → LAN
   # Ensure DHCP is enabled with range 10.0.100.10-10.0.100.100
   ```

3. **Check T-Pot network configuration:**
   ```bash
   # On T-Pot VM
   ip addr show
   ip route show
   cat /etc/resolv.conf
   
   # Should show:
   # IP: 10.0.100.10/24
   # Gateway: 10.0.100.1
   # DNS: 10.0.100.1
   ```

4. **Test connectivity step by step:**
   ```bash
   # From T-Pot VM
   ping 10.0.100.1          # Gateway (OPNsense LAN)
   ping 192.168.1.1         # Internet gateway
   ping 8.8.8.8             # External DNS
   nslookup google.com      # DNS resolution
   ```

### Problem: Cannot access T-Pot web interface

**Symptoms:**
- Browser timeout when accessing https://10.0.100.10:64297
- Connection refused error

**Solutions:**

1. **Check T-Pot service status:**
   ```bash
   # SSH to T-Pot VM
   sudo systemctl status tpot
   sudo docker ps
   sudo docker logs tpot_nginx_1
   ```

2. **Verify firewall rules:**
   ```bash
   # On T-Pot VM
   sudo ufw status
   sudo iptables -L
   
   # Port 64297 should be open
   sudo netstat -tlnp | grep 64297
   ```

3. **Check nginx configuration:**
   ```bash
   # On T-Pot VM
   sudo docker exec tpot_nginx_1 nginx -t
   sudo docker logs tpot_nginx_1
   ```

4. **Restart T-Pot services:**
   ```bash
   sudo systemctl restart tpot
   # Wait 2-3 minutes for all containers to start
   sudo docker ps
   ```

### Problem: Port forwarding not working

**Symptoms:**
- External scans don't reach T-Pot
- Honeypot services not accessible from internet

**Solutions:**

1. **Verify NAT rules in OPNsense:**
   ```bash
   # OPNsense Web Interface → Firewall → NAT → Port Forward
   # Check rules for ports 22, 80, 443
   # Ensure redirect target is 10.0.100.10
   ```

2. **Check firewall rules:**
   ```bash
   # OPNsense Web Interface → Firewall → Rules → WAN
   # Ensure corresponding firewall rules exist for NAT rules
   ```

3. **Test from external network:**
   ```bash
   # From external host
   nmap -p 22,80,443 YOUR_PUBLIC_IP
   telnet YOUR_PUBLIC_IP 22
   ```

4. **Check OPNsense logs:**
   ```bash
   # OPNsense Web Interface → System → Log Files → Firewall
   # Look for blocked connections
   ```

## VM Creation and Configuration

### Problem: VM fails to start

**Symptoms:**
- VM shows "stopped" status
- Console shows boot errors
- VM crashes during startup

**Solutions:**

1. **Check VM configuration:**
   ```bash
   # On Proxmox host
   qm config VM_ID
   
   # Verify:
   # - Sufficient memory (2GB for OPNsense, 8GB for T-Pot)
   # - Correct network bridges
   # - Boot order includes CD-ROM
   ```

2. **Check host resources:**
   ```bash
   # On Proxmox host
   free -h                  # Available memory
   df -h                    # Disk space
   cat /proc/cpuinfo        # CPU cores
   ```

3. **Review VM logs:**
   ```bash
   # On Proxmox host
   tail -f /var/log/syslog | grep "VM_ID"
   journalctl -u qemu-server@VM_ID
   ```

4. **Try different settings:**
   ```bash
   # Reduce memory allocation temporarily
   qm set VM_ID --memory 1024
   
   # Change CPU type
   qm set VM_ID --cpu host
   
   # Disable KVM acceleration if needed
   qm set VM_ID --kvm 0
   ```

### Problem: Bridge creation fails

**Symptoms:**
- `ifreload -a` command fails
- Bridge not visible in network interfaces
- VMs cannot connect to bridge

**Solutions:**

1. **Check network configuration syntax:**
   ```bash
   # On Proxmox host
   cat /etc/network/interfaces
   
   # Verify bridge configuration:
   auto vmbr1
   iface vmbr1 inet manual
       bridge-ports none
       bridge-stp off
       bridge-fd 0
   ```

2. **Manual bridge creation:**
   ```bash
   # On Proxmox host
   ip link add name vmbr1 type bridge
   ip link set vmbr1 up
   
   # Make permanent by adding to /etc/network/interfaces
   ```

3. **Check for conflicts:**
   ```bash
   # On Proxmox host
   ip link show                    # List all interfaces
   brctl show                      # Show bridge information
   ```

## OPNsense Firewall Issues

### Problem: Cannot access OPNsense web interface

**Symptoms:**
- Browser shows "connection timeout"
- HTTPS certificate errors
- Login page not loading

**Solutions:**

1. **Check OPNsense VM status:**
   ```bash
   # On Proxmox host
   qm status OPNSENSE_VM_ID
   
   # If stopped, start it:
   qm start OPNSENSE_VM_ID
   ```

2. **Verify network configuration:**
   ```bash
   # From OPNsense console
   # Option 1) Assign Interfaces
   # Ensure WAN = vtnet0, LAN = vtnet1
   
   # Option 2) Set interface IP address
   # Verify LAN IP is 10.0.100.1
   ```

3. **Reset to factory defaults (if needed):**
   ```bash
   # From OPNsense console
   # Option 4) Reset to factory defaults
   # WARNING: This will erase all configuration
   ```

4. **Check firewall rules:**
   ```bash
   # OPNsense Web Interface → Firewall → Rules → LAN
   # Ensure rule exists allowing LAN to This Firewall
   ```

### Problem: OPNsense loses configuration after reboot

**Symptoms:**
- Interface assignments reset
- Firewall rules disappear
- Need to reconfigure after each reboot

**Solutions:**

1. **Check disk space:**
   ```bash
   # From OPNsense console
   # Option 8) Shell
   df -h
   # Ensure sufficient space on root filesystem
   ```

2. **Verify configuration backup:**
   ```bash
   # OPNsense Web Interface → System → Configuration → Backups
   # Download current configuration
   # Check if configuration is being saved
   ```

3. **Check for hardware issues:**
   ```bash
   # On Proxmox host
   qm config OPNSENSE_VM_ID
   # Ensure disk is properly configured
   # Check VM disk integrity
   ```

## T-Pot Installation Problems

### Problem: T-Pot installation script fails

**Symptoms:**
- Installation stops with errors
- Docker containers fail to start
- Services not available after installation

**Solutions:**

1. **Check system requirements:**
   ```bash
   # On T-Pot VM
   free -h                  # Minimum 8GB RAM
   df -h                    # Minimum 128GB disk
   nproc                    # Minimum 4 CPU cores
   ```

2. **Verify internet connectivity:**
   ```bash
   # On T-Pot VM
   ping -c 3 8.8.8.8
   curl -I https://github.com
   ```

3. **Check Docker installation:**
   ```bash
   # On T-Pot VM
   sudo systemctl status docker
   sudo docker version
   sudo docker run hello-world
   ```

4. **Retry installation with debug:**
   ```bash
   # On T-Pot VM
   cd /opt/tpotce
   sudo bash -x ./install.sh
   ```

5. **Manual container check:**
   ```bash
   # After installation
   sudo docker ps -a
   sudo docker logs tpot_nginx_1
   sudo docker logs tpot_cowrie_1
   ```

### Problem: T-Pot services keep crashing

**Symptoms:**
- Docker containers restart frequently
- Services unavailable intermittently
- High CPU or memory usage

**Solutions:**

1. **Check resource usage:**
   ```bash
   # On T-Pot VM
   htop
   sudo docker stats
   ```

2. **Increase VM resources:**
   ```bash
   # On Proxmox host (VM must be stopped)
   qm set TPOT_VM_ID --memory 12288    # Increase to 12GB
   qm set TPOT_VM_ID --cores 6         # Increase to 6 cores
   ```

3. **Check disk space:**
   ```bash
   # On T-Pot VM
   df -h
   sudo docker system df
   
   # Clean up if needed
   sudo docker system prune -f
   ```

4. **Review container logs:**
   ```bash
   # On T-Pot VM
   sudo docker logs --tail 50 tpot_nginx_1
   sudo docker logs --tail 50 tpot_elasticsearch_1
   ```

## Performance Issues

### Problem: Slow T-Pot web interface

**Symptoms:**
- Dashboard takes long time to load
- Kibana is unresponsive
- High CPU usage on T-Pot VM

**Solutions:**

1. **Optimize Elasticsearch:**
   ```bash
   # On T-Pot VM
   sudo docker exec tpot_elasticsearch_1 curl -X PUT "localhost:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
   {
     "persistent": {
       "indices.memory.index_buffer_size": "20%"
     }
   }'
   ```

2. **Increase VM resources:**
   ```bash
   # On Proxmox host
   qm set TPOT_VM_ID --memory 16384    # 16GB RAM
   qm set TPOT_VM_ID --cores 8         # 8 CPU cores
   ```

3. **Configure log rotation:**
   ```bash
   # On T-Pot VM
   sudo nano /etc/logrotate.d/tpot
   
   # Add:
   /data/elk/logstash/logs/*.log {
       daily
       rotate 7
       compress
       delaycompress
       missingok
       notifempty
   }
   ```

### Problem: High network latency

**Symptoms:**
- Slow response times
- Packet loss
- Network timeouts

**Solutions:**

1. **Check Proxmox network configuration:**
   ```bash
   # On Proxmox host
   ethtool INTERFACE_NAME
   ip link show
   ```

2. **Optimize VM network settings:**
   ```bash
   # On Proxmox host
   qm set VM_ID --net0 virtio,bridge=vmbr1,queues=4
   ```

3. **Check for network congestion:**
   ```bash
   # On Proxmox host
   iftop -i vmbr0
   iftop -i vmbr1
   ```

## Security and Access Problems

### Problem: Cannot access from management network

**Symptoms:**
- Cannot reach OPNsense or T-Pot from LAN
- Firewall blocking legitimate access
- VPN connection issues

**Solutions:**

1. **Check firewall rules:**
   ```bash
   # OPNsense Web Interface → Firewall → Rules → LAN
   # Ensure management network is allowed
   ```

2. **Verify source IP:**
   ```bash
   # From management host
   curl ifconfig.me        # Check your public IP
   ip route get 8.8.8.8    # Check your local IP
   ```

3. **Add explicit allow rule:**
   ```bash
   # OPNsense Web Interface → Firewall → Rules → LAN
   # Add rule: Allow from YOUR_IP to This Firewall
   ```

### Problem: Honeypot receiving no attacks

**Symptoms:**
- No logs in T-Pot dashboard
- Attack map shows no activity
- Honeypot services not being discovered

**Solutions:**

1. **Verify external accessibility:**
   ```bash
   # From external network
   nmap -p 22,80,443 YOUR_PUBLIC_IP
   ```

2. **Check port forwarding:**
   ```bash
   # OPNsense Web Interface → Firewall → NAT → Port Forward
   # Verify all honeypot ports are forwarded
   ```

3. **Test with attack simulation:**
   ```bash
   # Run attack simulation script
   ./scripts/testing/attack-simulation.sh
   ```

4. **Check T-Pot service status:**
   ```bash
   # On T-Pot VM
   sudo docker ps
   sudo systemctl status tpot
   ```

## Monitoring and Logging Issues

### Problem: Logs not appearing in Kibana

**Symptoms:**
- Empty dashboards
- No data in Elasticsearch
- Logstash not processing logs

**Solutions:**

1. **Check Elasticsearch status:**
   ```bash
   # On T-Pot VM
   sudo docker logs tpot_elasticsearch_1
   curl -X GET "localhost:9200/_cluster/health"
   ```

2. **Verify Logstash configuration:**
   ```bash
   # On T-Pot VM
   sudo docker logs tpot_logstash_1
   sudo docker exec tpot_logstash_1 ls -la /etc/logstash/conf.d/
   ```

3. **Check log file permissions:**
   ```bash
   # On T-Pot VM
   sudo ls -la /data/
   sudo chown -R tpot:tpot /data/
   ```

4. **Restart ELK stack:**
   ```bash
   # On T-Pot VM
   sudo docker restart tpot_elasticsearch_1
   sudo docker restart tpot_logstash_1
   sudo docker restart tpot_kibana_1
   ```

## Common Error Messages

### "Connection refused" when accessing web interfaces

**Cause:** Service not running or firewall blocking connection

**Solution:**
```bash
# Check service status
sudo systemctl status SERVICE_NAME
sudo netstat -tlnp | grep PORT_NUMBER

# Check firewall
sudo ufw status
sudo iptables -L
```

### "No route to host" network errors

**Cause:** Network configuration issue or routing problem

**Solution:**
```bash
# Check routing table
ip route show

# Check interface status
ip link show

# Restart networking
sudo systemctl restart networking
```

### "Docker daemon not running"

**Cause:** Docker service stopped or failed to start

**Solution:**
```bash
# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Check Docker status
sudo systemctl status docker
sudo docker version
```

### "Insufficient disk space"

**Cause:** VM disk full or insufficient storage

**Solution:**
```bash
# Check disk usage
df -h

# Clean up Docker
sudo docker system prune -f

# Increase VM disk size (on Proxmox host)
qm resize VM_ID scsi0 +50G
```

### "Memory allocation failed"

**Cause:** Insufficient RAM allocated to VM

**Solution:**
```bash
# On Proxmox host (VM must be stopped)
qm set VM_ID --memory 8192    # Increase memory

# Check host memory
free -h
```

## Getting Help

### Log Collection

When seeking help, collect the following logs:

```bash
# System logs
sudo journalctl -xe > system.log

# T-Pot logs
sudo docker logs tpot_nginx_1 > tpot-nginx.log
sudo docker logs tpot_elasticsearch_1 > tpot-elasticsearch.log

# Network configuration
ip addr show > network-config.txt
ip route show >> network-config.txt

# Firewall status
sudo iptables -L > firewall-rules.txt
```

### Support Resources

- **T-Pot Community**: [GitHub Discussions](https://github.com/telekom-security/tpotce/discussions)
- **OPNsense Forum**: [https://forum.opnsense.org/](https://forum.opnsense.org/)
- **Proxmox Forum**: [https://forum.proxmox.com/](https://forum.proxmox.com/)

### Emergency Recovery

If the system becomes completely inaccessible:

1. **Reset OPNsense to factory defaults**
2. **Restore from backup configuration**
3. **Rebuild T-Pot VM from scratch**
4. **Check Proxmox host system logs**

---

**Remember**: Always backup configurations before making changes, and test in a lab environment first!