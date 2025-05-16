# Script by Mayumi
# Edited by SadCat


import socket
import ssl
import json
import concurrent.futures
import re
import threading

IP_RESOLVER = "speed.cloudflare.com"
PATH_RESOLVER = "/meta"
PROXY_FILE = "Orange/SadCat.txt"
OUTPUT_FILE = "Orange/alivecat.txt"
OUTPUT_JSON_FILE = "Orange/alivecat.json"  # New JSON output file

active_proxies = []  # List to store active proxies for TXT
json_proxies = {}    # Dictionary to store active proxies for JSON
lock = threading.Lock()  # Lock for thread-safe updates to json_proxies

def check(host, path, proxy):
    payload = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240\r\n"
        "Connection: close\r\n\r\n"
    )

    ip = proxy.get("ip", host)
    port = int(proxy.get("port", 443))

    conn = None
    try:
        ctx = ssl.create_default_context()
        conn = socket.create_connection((ip, port), timeout=5)
        conn = ctx.wrap_socket(conn, server_hostname=host)

        conn.sendall(payload.encode())

        resp = b""
        while True:
            data = conn.recv(4096)
            if not data:
                break
            resp += data

        resp = resp.decode("utf-8", errors="ignore")
        headers, body = resp.split("\r\n\r\n", 1)

        return json.loads(body)
    except (json.JSONDecodeError, ValueError):
        print(f"Error parsing JSON from {ip}:{port}")
    except (socket.error, ssl.SSLError) as e:
        print(f"Error connection: {e}")
    finally:
        if conn:
            conn.close()

    return {}

def clean_org_name(org_name):
    return re.sub(r'[^a-zA-Z0-9\s]', '', org_name) if org_name else org_name

def process_proxy(proxy_line):
    proxy_line = proxy_line.strip()
    if not proxy_line:
        return

    try:
        ip, port, country, org = proxy_line.split(",")
        proxy_data = {"ip": ip, "port": port}

        ori, pxy = [
            check(IP_RESOLVER, PATH_RESOLVER, {}),
            check(IP_RESOLVER, PATH_RESOLVER, proxy_data)
        ]

        if ori and pxy and ori.get("clientIp") != pxy.get("clientIp"):
            org_name = clean_org_name(pxy.get("asOrganization"))
            proxy_country = pxy.get("country")

            proxy_entry = f"{ip},{port},{country},{org_name}"
            print(f"CF PROXY LIVE!: {proxy_entry}")
            active_proxies.append(proxy_entry)

            # Add to JSON structure
            country_code = country.strip().upper()
            ip_port = f"{ip}:{port}"
            with lock:
                if country_code not in json_proxies:
                    json_proxies[country_code] = []
                json_proxies[country_code].append(ip_port)
        else:
            print(f"CF PROXY DEAD!: {ip}:{port}")

    except ValueError:
        print(f"Proxy lines was not valid: {proxy_line}. Make sure the proxy format like: ip,port,country,org")
    except Exception as e:
        print(f"Error while processing the proxy {proxy_line}: {e}")

# Delete the output file if it exists
open(OUTPUT_FILE, "w").close()
print(f"File {OUTPUT_FILE} was deleted before scanning proxy start.")

# Read proxy from file
try:
    with open(PROXY_FILE, "r") as f:
        proxies = f.readlines()
except FileNotFoundError:
    print(f"File not found: {PROXY_FILE}")
    exit()

max_workers = 20

with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
    futures = [executor.submit(process_proxy, proxy_line) for proxy_line in proxies]
    concurrent.futures.wait(futures)

# Save file TXT dan JSON
if active_proxies:
    with open(OUTPUT_FILE, "w") as f_me:
        f_me.write("\n".join(active_proxies) + "\n")
    print(f"All proxy saved in {OUTPUT_FILE} file.")

if json_proxies:
    with open(OUTPUT_JSON_FILE, "w") as f_json:
        json.dump(json_proxies, f_json, indent=2)
    print(f"Active proxy saved in {OUTPUT_JSON_FILE} for JSON format.")
else:
    print("None active proxy saved in the JSON.")

print("Checking proxy completed.")