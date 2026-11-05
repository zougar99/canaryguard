"""Credential-graph clustering — A4 from the roadmap.

Builds a bipartite graph (source IP <-> credential artifacts) from the
`creds` table and finds connected components. A component containing many
distinct IPs that all tried the same password is a credential-stuffing
botnet; one IP cycling many usernames is password spraying.

Passwords are never echoed raw — only masked fingerprints.
"""

import hashlib

from .spray import mask_password


def _pw_node(pw):
    return "pw:" + hashlib.sha256((pw or "").encode("utf-8", "ignore")).hexdigest()[:16]


def _hash_node(kind, value):
    return f"{kind}:" + hashlib.sha256((value or "").encode("utf-8", "ignore")).hexdigest()[:16]


class UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        parent = self.parent
        if x not in parent:
            parent[x] = x
            return x
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def analyze(rows, min_ips=3, mask=True):
    """rows: iterable of dicts with src_ip, username, password.

    Returns {"clusters": [...], "stats": {...}} where each cluster is a
    connected component linking >= min_ips distinct IPs or >= min_ips usernames.
    """
    uf = UnionFind()
    ip_nodes, pw_nodes, user_nodes = set(), {}, set()
    pw_meta = {}  # pw node -> (masked, raw_hash)

    for row in rows:
        ip = (row.get("src_ip") or "").strip()
        user = (row.get("username") or "").strip().lower()
        pw = (row.get("password") or "")
        if not ip:
            continue
        ip_node = f"ip:{ip}"
        ip_nodes.add(ip_node)
        uf.find(ip_node)
        if pw:
            node = _pw_node(pw)
            pw_nodes[node] = ip
            pw_meta.setdefault(node, (mask_password(pw) if mask else pw, node))
            uf.union(ip_node, node)
        if user:
            node = _hash_node("user", user)
            user_nodes.add(node)
            uf.union(ip_node, node)

    components = {}
    for node in list(uf.parent):
        components.setdefault(uf.find(node), []).append(node)

    clusters = []
    for members in components.values():
        ips = sorted(m[3:] for m in members if m.startswith("ip:"))
        pws = [m for m in members if m.startswith("pw:")]
        users = [m for m in members if m.startswith("user:")]
        if len(ips) >= min_ips and (pws or users):
            clusters.append({
                "size": len(members),
                "ips": ips,
                "distinct_ips": len(ips),
                "passwords": [pw_meta[p][0] for p in pws if p in pw_meta],
                "distinct_passwords": len(pws),
                "distinct_usernames": len(users),
            })
    clusters.sort(key=lambda c: (c["distinct_ips"], c["distinct_passwords"]), reverse=True)
    return {
        "clusters": clusters,
        "stats": {
            "ips_tracked": len(ip_nodes),
            "components": len(components),
            "min_ips": min_ips,
        },
    }


def analyze_store(store, min_ips=3, limit=5000):
    rows = store.fetchall(
        "SELECT src_ip, username, password FROM creds ORDER BY id DESC LIMIT ?",
        (int(limit),),
    )
    for row in rows:  # passwords are encrypted at rest — decrypt for analysis
        from .cryptostore import decrypt

        row["password"] = decrypt(row.get("password"))
    return analyze(rows, min_ips=min_ips)
