#!/usr/bin/env python3
import os
import sys
import subprocess
import redis

# ===== Environment =====
REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
CHANNEL   = os.environ.get("FW_CHANNEL", "fw:events")

# ===== Redis keys =====
K_BLACK_IPS    = "fw:blacklist:ips"
K_BLOCK_PORTS  = "fw:block:ports"
K_ALLOW_IPPORT = "fw:allow:ipports"
K_BLOCK_IPPORT = "fw:block:ipports"

# ===== ipset set names =====
SET_BLACK_IPS    = "fw_black_ips"
SET_BLOCK_PORTS  = "fw_block_ports"
SET_ALLOW_IPPORT = "fw_allow_ipports"
SET_BLOCK_IPPORT = "fw_block_ipports"

def sh(cmd: str) -> int:
  rc = subprocess.call(cmd, shell=True)
  if rc != 0:
    sys.stderr.write(f"[redis-fw-agent] CMD FAIL ({rc}): {cmd}\n")
  return rc

def ipset_create():
  sh(f"ipset create {SET_BLACK_IPS} hash:ip -exist")
  sh(f"ipset create {SET_BLOCK_PORTS} bitmap:port range 1-65535 -exist")
  sh(f"ipset create {SET_ALLOW_IPPORT} hash:ip,port -exist")
  sh(f"ipset create {SET_BLOCK_IPPORT} hash:ip,port -exist")

def ipset_restore_from_redis(r: redis.Redis):
  # Flush all sets before restore
  sh(f"ipset flush {SET_BLACK_IPS}")
  sh(f"ipset flush {SET_BLOCK_PORTS}")
  sh(f"ipset flush {SET_ALLOW_IPPORT}")
  sh(f"ipset flush {SET_BLOCK_IPPORT}")

  # Restore IP blacklist
  for ip in r.smembers(K_BLACK_IPS):
    if isinstance(ip, bytes): ip = ip.decode()
    if ip:
      sh(f"ipset add {SET_BLACK_IPS} {ip} -exist")

  # Restore blocked ports
  for p in r.smembers(K_BLOCK_PORTS):
    if isinstance(p, bytes): p = p.decode()
    if p:
      sh(f"ipset add {SET_BLOCK_PORTS} {p} -exist")

  # Restore allow ip:port
  for s in r.smembers(K_ALLOW_IPPORT):
    s = s.decode() if isinstance(s, bytes) else s
    if s and ':' in s:
      ip, port = s.split(':', 1)
      sh(f"ipset add {SET_ALLOW_IPPORT} {ip},tcp:{port} -exist")

  # Restore block ip:port
  for s in r.smembers(K_BLOCK_IPPORT):
    s = s.decode() if isinstance(s, bytes) else s
    if s and ':' in s:
      ip, port = s.split(':', 1)
      sh(f"ipset add {SET_BLOCK_IPPORT} {ip},tcp:{port} -exist")

def ensure_iptables():
  # Blacklisted IPs → DROP
  sh(f"iptables -C INPUT -m set --match-set {SET_BLACK_IPS} src -j DROP 2>/dev/null || "
     f"iptables -I INPUT -m set --match-set {SET_BLACK_IPS} src -j DROP")
  # Blocked ports → DROP
  sh(f"iptables -C INPUT -p tcp -m set --match-set {SET_BLOCK_PORTS} dst -j DROP 2>/dev/null || "
     f"iptables -I INPUT -p tcp -m set --match-set {SET_BLOCK_PORTS} dst -j DROP")
  # Block ip:port → DROP
  sh(f"iptables -C INPUT -p tcp -m set --match-set {SET_BLOCK_IPPORT} src,dst -j DROP 2>/dev/null || "
     f"iptables -I INPUT -p tcp -m set --match-set {SET_BLOCK_IPPORT} src,dst -j DROP")
  # Allow ip:port → ACCEPT (place before global port DROPs)
  sh(f"iptables -C INPUT -p tcp -m set --match-set {SET_ALLOW_IPPORT} src,dst -j ACCEPT 2>/dev/null || "
     f"iptables -I INPUT -p tcp -m set --match-set {SET_ALLOW_IPPORT} src,dst -j ACCEPT")

def handle(msg: str):
  parts = (msg or "").strip().split()
  if not parts:
    return
  cmd  = parts[0]
  arg1 = parts[1] if len(parts) > 1 else None
  arg2 = parts[2] if len(parts) > 2 else None

  # IP blacklist
  if cmd == "ban_ip" and arg1:
    sh(f"ipset add {SET_BLACK_IPS} {arg1} -exist")
  elif cmd == "unban_ip" and arg1:
    sh(f"ipset del {SET_BLACK_IPS} {arg1} 2>/dev/null")

  # Port block
  elif cmd == "block_port" and arg1:
    sh(f"ipset add {SET_BLOCK_PORTS} {arg1} -exist")
  elif cmd == "unblock_port" and arg1:
    sh(f"ipset del {SET_BLOCK_PORTS} {arg1} 2>/dev/null")

  # Allow ip:port
  elif cmd == "allow_ipport" and arg1 and arg2:
    #sh(f"ipset add {SET_ALLOW_IPPORT} {arg1},{arg2} -exist")
    sh(f"ipset add {SET_ALLOW_IPPORT} {arg1},tcp:{arg2} -exist")
  elif cmd == "unallow_ipport" and arg1 and arg2:
    #sh(f"ipset del {SET_ALLOW_IPPORT} {arg1},{arg2} 2>/dev/null")
    sh(f"ipset del {SET_ALLOW_IPPORT} {arg1},tcp:{arg2} 2>/dev/null")

  # Block ip:port
  elif cmd == "block_ipport" and arg1 and arg2:
    #sh(f"ipset add {SET_BLOCK_IPPORT} {arg1},{arg2} -exist")
    sh(f"ipset add {SET_BLOCK_IPPORT} {arg1},tcp:{arg2} -exist")
  elif cmd == "unblock_ipport" and arg1 and arg2:
    #sh(f"ipset del {SET_BLOCK_IPPORT} {arg1},{arg2} 2>/dev/null")
    sh(f"ipset del {SET_BLOCK_IPPORT} {arg1},tcp:{arg2} 2>/dev/null")

def main():
  r = redis.from_url(REDIS_URL, decode_responses=False)
  ipset_create()
  ensure_iptables()
  ipset_restore_from_redis(r)

  ps = r.pubsub()
  ps.subscribe(CHANNEL)
  for item in ps.listen():
    if item.get("type") != "message":
      continue
    data = item.get("data")
    if isinstance(data, bytes):
      data = data.decode()
    try:
      handle(data)
    except Exception:
      # Keep agent running even if a message causes an error
      pass

if __name__ == "__main__":
  try:
    main()
  except Exception as e:
    sys.stderr.write(f"[redis-fw-agent] fatal: {e}\n")
    sys.exit(1)