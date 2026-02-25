# Algorithm Overview — PU-CP-ABE Hybrid Implementation

All algorithms are implemented in `ta_local.py` (1195 lines). This document maps the paper's theoretical algorithms to the actual code, using real function names and data structures.

---

## Policy Representation

### AST Nodes

```python
@dataclass(frozen=True)
class Leaf:
    name: str                    # e.g., "attA"

@dataclass(frozen=True)
class Gate:
    kind: str                    # "AND" / "OR" / "THRESH"
    k: int                       # threshold k-of-n
    children: List[Node]         # child Leaf or Gate nodes
```

### Policy Grammar (tokenizer + recursive descent parser)

```
policy ::= leaf_name
         | "(" policy AND policy ")"
         | "(" policy OR  policy ")"
         | "(" k "," policy "," policy "," ... ")"   ← k-of-n threshold

leaf_name ::= [A-Za-z0-9_]+
k         ::= integer

# Single-attribute edge case: "attA" → normalized to "(attA AND attA)"
# (ensures tree always has ≥ 1 internal node for the structure table)
```

### Structure Table (`build_structure_table(root)`)

Returns one row per subtree (non-leaf node):

```python
{
    "Subtree":      "T1",           # label (Tr = root, T1, T2, ...)
    "RootName":     "s1",           # key in CT[_debug][s_map]
    "Threshold":    2,              # t_j
    "Leaf nodes":   {"attA","attB"},# L_j (attribute name strings)
    "Non-leaf nodes": {"T2"},       # N_j (subtree labels)
    "Satisfying non-leaf nodes": {} # computed during decrypt
}
```

---

## 1. ThresholdABE.setup() → (msk, mpk)

**Runs:** local TA machine · **Output:** `keys/ta_setup.json`

```python
group = PairingGroup("SS512")  # 512-bit Type-A symmetric pairing, ~80-bit security

# g  ∈ G1  (generator)
# g2 ∈ G2  (separate generator for key components)
# h[0..2l] ∈ G2  (public hash parameters, l = ell = attribute universe size)
# α, β ∈ ZR  (master secret scalars)
# g1 = g^α
# v, w chosen such that e(g1, g2) = e(v^β, w^{1/β})

mpk = {
    "g":   g,            # G1 generator
    "g2":  g2,           # G2 generator
    "vb":  v**beta,      # v^β ∈ G2
    "h":   {0: h0, 1: h1, ..., 2*l: h2l},   # G2 elements (dict, str/int keyed)
    "egg": pair(g1, g2), # e(g1, g2) ∈ GT — used in Encrypt + Decrypt
}
msk = {
    "alpha": alpha,      # ZR scalar
    "w_inv": w**(~beta), # w^{1/β} ∈ G2 — used in KeyGen
    "g1":    g1,         # g^α ∈ G1
}
```

**Saved to `ta_setup.json`:** `{curve, ell, mpk: serialize_any(group, mpk), msk: serialize_any(group, msk)}`

The cloud reads this file but should use only `mpk`. `msk` is present in the PoC for convenience — see security gaps.

---

## 3. ThresholdABE.keygen(msk, mpk, A_idx) → sk_A

**Runs:** local TA machine · **Output:** `keys/user_sk.json`

```python
# A_idx: set of integer attribute indices from rho mapping
# U_prime = {l+1, ..., 2l}  (dummy/default attributes for all users)
# all_t = A_idx ∪ U_prime

r = group.random(ZR)    # FRESH per call — collusion resistance

# Polynomial q of degree l-1, q(0) = alpha
# Evaluates via Lagrange basis: q(i) for each i in all_t

for t in all_t:
    rqt = r * q(t)
    SK[str(t)] = {
        "sk0": (g2 * h[0] * h[t]) ** rqt,        # (g2·h0·h_t)^{r·q(t)} ∈ G2
        "sk1": mpk["g"] ** rqt,                   # g^{r·q(t)} ∈ G1
        "sk2": [h[i]**rqt for i in 1..2l if i≠t], # {h_i^{r·q(t)}} ∈ G2
        "d":   msk["w_inv"] ** r,                 # w^{(r-1)/β} ∈ G2
    }

SK["_meta"] = {"r": r, "alpha": alpha}    # debug metadata
```

**Why fresh `r` prevents collusion:** Decryption requires combining `SK[i]["sk0"]^{delta_i}` via Lagrange. With two keys using `r1 ≠ r2`, the combination equals `(g2 h0 ∏h_t)^{r1·... + r2·...}` instead of `^{rα}`, so `D_{j,1} ≠ e(g2^{rα}, g^{s_j})` and decryption fails.

---

## 4. ThresholdABE.encrypt(K_gt, mpk, policy) → CT

**Runs:** Lambda (called from `lambda_encrypt.py`) · **Input:** `K_gt` is a `GT` element, NOT raw bytes

```python
# Parse policy → access tree; build structure table → rows
# rho: {attr_name: integer_index}  (first-seen order)

for row in build_structure_table(parse_policy(policy)):
    j     = row["Subtree"]          # e.g., "T1"
    s_j   = group.random(ZR)        # fresh random secret per subtree
    t_j   = row["Threshold"]
    L_j   = [rho[a] for a in row["Leaf nodes"]]
    N_j   = row["Non-leaf nodes"]   # subtree labels of non-leaf children
    Omega = list(range(l+1, 2*l - t_j + 1))   # default attr indices

    # ct1: (h0 · ∏_{i ∈ L_j ∪ Ω_j} h_i)^{s_j}   ∈ G2
    ct1 = prod(h[i] for i in [0]+L_j+Omega) ** s_j

    # ct2: g^{s_j}   ∈ G1
    ct2 = mpk["g"] ** s_j

    # For each non-leaf child T_k with secret s_k:
    # ct_{i+2} = h_{2l - t_j + i}^{s_j} · g2^{s_k}   ∈ G2
    for i, child_label in enumerate(sorted(N_j), start=1):
        s_k = s_map[child_rname]    # s_k already assigned for child subtree
        ct[f"ct{i+2}"] = h[2*l - t_j + i] ** s_j * mpk["g2"] ** s_k

    ct_T[j] = {"ct1": ct1, "ct2": ct2, **ct_nonleaf}
    s_map[row["RootName"]] = s_j    # "sr", "s1", "s2", ...

# Root blinding (Tr):
s_r = s_map["sr"]
CT = {
    "C0":      K_gt * mpk["egg"] ** s_r,    # K_gt · e(g1,g2)^{s_r}  ∈ GT
    "C1":      mpk["vb"] ** s_r,            # (v^β)^{s_r}  ∈ G2
    "ct_T":    ct_T,
    "policy":  policy,
    "rho":     rho,
    "ell":     l,
    "_debug":  {"s_map": s_map},    # ← E_T: used by UPKeyGen
}
```

**Hybrid layer in `lambda_encrypt.py`:**
```python
K_gt   = ctx.group.random(GT)                      # random session key
dek32  = hashlib.sha256(ctx.group.serialize(K_gt)).digest()  # KDF → 32B
c_aes  = AES_GCM_encrypt(M, dek32, aad=object_id.encode())  # AAD bound
ct_abe = ctx.abe.encrypt(K_gt, ctx.mpk, policy)    # ABE on GT element only
```

---

## 5. ThresholdABE.decrypt(CT, SK, mpk, attrs) → K_gt

**Runs:** local client (`client_decrypt.py`) · **Returns:** GT element

Recursive bottom-up traversal. `_abe_decrypt_flexible()` tries four signature variants to handle potential API differences.

```python
memo = {}

def dec_subtree(Tname):
    row   = structure_table[Tname]
    t_j   = row["Threshold"]
    L_j   = row["Leaf nodes"]           # attr name strings
    N_j   = row["Non-leaf nodes"]       # subtree labels
    Omega = list(range(l+1, 2*l - t_j + 1))

    ct_j  = CT["ct_T"][Tname]
    ctj1, ctj2 = ct_j["ct1"], ct_j["ct2"]

    # Recursively decrypt satisfied non-leaf children
    S_j = {}
    for child in N_j:
        try:
            D_k1, P_k2 = dec_subtree(child)
            S_j[child] = (D_k1, P_k2)
        except ValueError:
            pass

    # Choose t_j satisfying attrs from L_j ∩ attrs + subtrees + Omega
    A_prime_j = choose_satisfying_subset(attrs ∩ L_j, S_j, t_j)
    combo = list(A_prime_j) + list(S_j.keys()) + Omega

    if len(A_prime_j) + len(S_j) < t_j:
        raise ValueError("Policy not satisfied at subtree " + Tname)

    # D_{j,3,k}: contribution from each satisfied non-leaf child
    D_j3_prod = GT.identity
    for i, (child, (D_k1, P_k2)) in enumerate(S_j.items(), start=1):
        ct_k = ct_j[f"ct{i+2}"]
        D_j3_prod *= pair(ct_k, P_k2) / D_k1

    # Lagrange combine: P_{j,1} = ∏ sk0_t^{delta_t},  P_{j,2} = ∏ sk1_t^{delta_t}
    P_j1, P_j2 = G2.identity, G1.identity
    for t in combo:
        t_idx  = rho[t] if isinstance(t, str) else t
        delta  = lagrange_coeff(t_idx, [rho[x] if isinstance(x,str) else x
                                        for x in combo], 0)
        P_j1  *= SK[str(t_idx)]["sk0"] ** delta
        P_j2  *= SK[str(t_idx)]["sk1"] ** delta

    # D_{j,1} = e(g2^{rα}, g^{s_j})
    base = prod(h[i] for i in [0] + L_j_int + Omega)   # h0·∏h_i
    D_j1 = pair(P_j1, ctj2) / (pair(base ** s_j_exp, P_j2) * D_j3_prod)
    return D_j1, P_j2

Dr1, _ = dec_subtree("Tr")
# Dr2 = e((v^β)^{s_r}, w^{(r-1)/β})  = e(g2^{rα}, g^{s_r}) · e(g2^α, g^{-s_r})
Dr2  = pair(CT["C1"], SK[any_i]["d"])
K_gt = CT["C0"] * (Dr2 / Dr1)    # = K_gt · e(g1,g2)^{s_r} / e(g2^α,g^{s_r}) ✓
```

**Client recovery:**
```python
K_gt  = _abe_decrypt_flexible(abe, mpk, sk, ct_abe_raw, attrs)
dek32 = hashlib.sha256(group.serialize(K_gt)).digest()
pt    = AESGCM(dek32).decrypt(nonce, ct, aad=object_id.encode())
```

---

## 6. UPKeyGen(group, params, ell, E_T, old_policy, new_policy, target_subtree, mode) → tk

**Runs:** cloud (`cloud_update.py` calls this from `ta_local.py`)

**`E_T`** is read from `CT["_debug"]["s_map"]` in the stored record. (PoC gap: in production E_T would be managed separately by the Data Owner.)

```python
old_root = parse_policy(old_policy)
new_root = parse_policy(new_policy)
rho_new  = _make_rho_from_policy(new_root, ell)

row_old  = _row_by_subtree(old_root, target_subtree)
row_new  = _row_by_subtree(new_root, target_subtree)

s_j     = E_T[row_old["RootName"]]   # e.g., E_T["s1"]

base_old = h[0] * prod(h[i] for i in L_j_old + Omega_old)
base_new = h[0] * prod(h[i] for i in L_j_new + Omega_new)

tprime   = group.random(ZR)
tk_j1    = (base_new ** s_j) * (base_old ** (-s_j * tprime))
# = base_new^{s_j} · base_old^{-s_j·t'}  ∈ G2

if mode == "Attributes2Existing":
    # Update key: 2 elements — constant size
    return {
        "type":           "Attributes2Existing",
        "old_policy":     old_policy,
        "new_policy":     new_policy,
        "target_subtree": target_subtree,
        "tprime":         tprime,    # ZR scalar
        "tk_j1":          tk_j1,     # G2 element
    }

elif mode == "Attributes2New":
    # Additional: new subtree ciphertext + tk_leaf
    row_t  = _row_by_subtree(new_root, new_subtree)
    s_t    = E_T[row_t["RootName"]]

    # Build ct_{Tt} for newly introduced gate (same structure as Encrypt)
    ct_Tt  = {"ct1": prod_t ** s_t, "ct2": g ** s_t,
               **{f"ct{i+2}": h[2l-t_t+i]**s_t * g2**s_child
                  for i,s_child in enumerate(child_secrets)}}

    # tk_leaf = h_{2l - t_j(new) + pos}^{s_j} · g2^{s_t}
    tk_leaf = h[2*l - tj_new + pos_new_gate] ** s_j * params["g2"] ** s_t

    return {
        "type": "Attributes2New", "tprime": tprime, "tk_j1": tk_j1,
        "new_subtree": new_subtree, "pos_new_gate": pos_new_gate,
        "ct_Tt": ct_Tt, "tk_leaf": tk_leaf, ...
    }
```

---

## 7. CTUpdate(CT, tk) → CT'

**Runs:** cloud (`cloud_update.py`)

```python
# IMPORTANT: uses dict(CT) not deepcopy() — charm pairing.Element not picklable
CTp = dict(CT)
CTp["ct_T"] = dict(CT["ct_T"])

Tj     = tk["target_subtree"]
ctj    = CT["ct_T"][Tj]

# Only ct1 changes; ct2 and ctN are preserved
ct1_new = (ctj["ct1"] ** tk["tprime"]) * tk["tk_j1"]

ctj_new = {k: v for k,v in ctj.items() if k != "ct1"}
ctj_new["ct1"] = ct1_new

if tk["type"] == "Attributes2New":
    ctj_new["ct_new_leaf"] = tk["tk_leaf"]
    CTp["ct_T"][tk["new_subtree"]] = tk["ct_Tt"]   # add new subtree

CTp["ct_T"][Tj] = ctj_new
CTp["policy"]   = tk["new_policy"]
CTp["rho"]      = _make_rho_from_policy(parse_policy(tk["new_policy"]), ell)
# C0, C1 (root blinding) unchanged → K_gt still encapsulated correctly
# _debug (s_map) preserved → future UPKeyGen can still read E_T
```

**What changes vs what stays the same:**

| Component | Updated? |
|---|---|
| `CT["ct_T"][Tj]["ct1"]` | ✓ Yes — reflects new attribute set |
| `CT["ct_T"][Tj]["ct2"]`, `ctN` | ✗ Preserved |
| `CT["C0"]`, `CT["C1"]` | ✗ Preserved — K_gt still inside |
| `c_aes` (AES ciphertext) | ✗ Never touched — M unchanged |
| `CT["policy"]`, `CT["rho"]` | ✓ Updated to new policy string |

---

## 8. Serialization

```python
def serialize_any(group, obj):
    try:
        b = group.serialize(obj)    # charm element → bytes
        return {"__charm__": base64.b64encode(b).decode("ascii")}
    except:
        pass
    if isinstance(obj, dict):
        return {str(k): serialize_any(group, v) for k,v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [serialize_any(group, v) for v in obj]
    return obj   # int, str, float pass through

def deserialize_any(group, obj):
    if isinstance(obj, dict) and "__charm__" in obj:
        return group.deserialize(base64.b64decode(obj["__charm__"]))
    if isinstance(obj, dict):
        return {k: deserialize_any(group, v) for k,v in obj.items()}
    if isinstance(obj, list):
        return [deserialize_any(group, v) for v in obj]
    return obj
```

**Critical constraint:** `group.serialize` / `group.deserialize` are specific to the `PairingGroup("SS512")` instance. Both cloud and client must call `build_abe(curve, ell)` with the same `curve` and `ell` values stored in `ta_setup.json`.

---

## 9. crypto_core.py (Test/CI Helper)

`crypto_core.py` provides `encrypt_bytes()` and `decrypt_bytes()` as subprocess wrappers. The test suite uses these so tests don't need to import charm-crypto directly:

```python
def encrypt_bytes(plaintext: bytes, policy: str, keys_dir: str = "keys") -> dict:
    # diffs os.listdir(store_dir) before/after to find new object_id
    cmd = [sys.executable, "lambda_encrypt.py",
           "--setup", setup_path, "--policy", policy,
           "--plaintext", plaintext.decode(), "--store-dir", store_dir]
    out = _run(cmd)
    oid = _extract_oid(out)   # parses {"object_id": "..."} from stdout
    return {"object_id": oid, "store_dir": store_dir, ...}

def decrypt_bytes(bundle: dict, attrs: str, sk_path: str) -> bytes:
    cmd = [sys.executable, "client_decrypt.py",
           "--object_id", bundle["object_id"],
           "--attrs", attrs, "--store_dir", bundle["store_dir"], ...]
    out = _run(cmd)
    # filters DEBUG/INFO/WARN/ERROR prefix lines; returns last non-empty line
    return last_clean_line(out).encode("utf-8")
```
