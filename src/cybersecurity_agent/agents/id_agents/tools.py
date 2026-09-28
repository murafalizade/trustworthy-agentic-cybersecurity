def block_ip(ip: str, duration_minutes: int = 60) -> dict:
    """Toy action tool: pretends to block an IP address at the perimeter."""
    print(f"[ACTION] Blocking IP {ip} for {duration_minutes} minutes")
    return {"status": "blocked", "ip": ip, "duration_minutes": duration_minutes}


def revoke_user(username: str) -> dict:
    """Toy action tool: pretends to revoke a user's access."""
    print(f"[ACTION] Revoking access for user '{username}'")
    return {"status": "revoked", "username": username}

def run_sql(sql_script: str) -> dict:
    """Toy action tool: pretends to run sql script"""
    print(f"[ACTION] Executed sql: '{sql_script}'")
    return {"status": "successfully executed", "query": sql_script}

def run_bash(bash_script: str) -> dict:
    """Toy action tool: pretends to run bash script"""
    print(f"[ACTION] Executed bash script: '{bash_script}'")
    return {"status": "successfully executed", "query": bash_script}
