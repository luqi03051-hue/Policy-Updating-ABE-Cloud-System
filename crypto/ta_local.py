# TA_LOCAL_VERSION: 2026-02-11-fixed (no module-level demo code; includes _make_rho_from_policy)
# -*- coding: utf-8 -*-
"""
ta_local.py  (Trusted Authority + shared ABE core)

This file contains:
1) The ABE scheme implementation (ThresholdABE) + policy parser
2) Serialization helpers for Charm pairing elements
3) TA role utilities:
   - Setup() -> (mpk, msk)
   - KeyGen(msk, A) -> sk_A

Why keep "core" here?
- So your Lambda-side code and Client-side code can simply import the same scheme:
    from ta_local import build_abe, serialize_any, deserialize_any
- This matches your paper roles while keeping the engineering clean.

NOTE:
- In a production system you would NOT ship msk outside TA.
- You would NOT upload users' secret keys to the cloud.
- For this PoC, we store mpk/msk/sk locally as JSON (base64-serialized elements).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair


# ============================================================
# 0) Small helpers: base64 + JSON
# ============================================================
def normalize_policy(policy: str) -> str:
    p = (policy or "").strip()
    # 单个属性：只含字母数字下划线/连字符（按你属性命名习惯调整）
    if re.fullmatch(r"[A-Za-z0-9_-]+", p):
        return f"({p} AND {p})"
    return policy

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def save_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ============================================================
# 1) Serialization helpers for Charm pairing elements
# ============================================================

def serialize_any(group, obj: Any) -> Any:
    """
    Cross-version serializer for Charm objects.
    We avoid relying on pairing.Element type (varies across Charm versions).
    Strategy: try group.serialize(obj); if it works, treat it as a pairing element.
    """
    # 1) pairing element?
    try:
        b = group.serialize(obj)
        return {"__charm__": b64e(b)}
    except Exception:
        pass

    # 2) containers
    if isinstance(obj, dict):
        return {str(k): serialize_any(group, v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [serialize_any(group, v) for v in obj]
    if isinstance(obj, tuple):
        return [serialize_any(group, v) for v in obj]  # store tuple as list

    # 3) primitives
    return obj



def deserialize_any(group, obj: Any) -> Any:
    """
    Reverse of serialize_any().
    """
    if isinstance(obj, dict) and "__charm__" in obj:
        return group.deserialize(b64d(obj["__charm__"]))
    if isinstance(obj, dict):
        return {k: deserialize_any(group, v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [deserialize_any(group, v) for v in obj]
    return obj



# ------------------------------------------------------------
# Pairing parameter access helper
# ------------------------------------------------------------
def h_get(params: Dict[str, Any], idx: int):
    """Get params['h'][idx] robustly across JSON (string keys) and in-memory (int keys)."""
    h = params.get("h", {})
    k = str(idx)
    if isinstance(h, dict):
        if k in h:
            return h[k]
        if idx in h:
            return h[idx]
    raise KeyError(f"params['h'] missing index {idx}")
# ============================================================
# 2) Your full ABE core (paper-faithful Encrypt/Decrypt)
#    (copied from your local ABE reference file)
# ============================================================

# -*- coding: utf-8 -*-
"""
Threshold ABE (access-tree with AND/OR/threshold gates) — reference implementation in Charm-Crypto.

This script includes:
- Policy tokenizer + recursive-descent parser: AND/OR + threshold gate (k, expr1, expr2, ...)
- Access-tree traversal to build structure table and Tab II-like node sets (including satisfying non-leaf nodes)
- ThresholdABE: Setup / KeyGen / Encrypt / Decrypt
- A minimal runnable demo under __main__

Notes:
- This implementation follows the algebraic structure used in your screenshots:
  Each satisfied subtree T_j computes D_{j,1} = e(g2^{rα}, g^{s_j}) and P_{j,2} = g^{rα}.
  Finally, recover M via: M = C0 * (D_{r,2} / D_{r,1}).
- IMPORTANT: Use an asymmetric pairing group and place g in G1, g2 and h_i in G2.
"""

from dataclasses import dataclass
from typing import List, Union, Optional, Set, Dict, Any
from copy import deepcopy

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair


# ============================================================
# 1) Policy AST Nodes
# ============================================================
@dataclass(frozen=True)
class Leaf:
    name: str


@dataclass(frozen=True)
class Gate:
    kind: str               # "AND" / "OR" / "THRESH"
    k: int                  # threshold k-of-n
    children: List["Node"]


Node = Union[Leaf, Gate]


# ============================================================
# 2) Tokenizer
# ============================================================
def tokenize(s: str) -> List[str]:
    """
    Split policy string into tokens:
    - '(' , ')' , ','
    - AND / OR
    - attribute names: attA, att_B, A1, ...
    - digits for threshold gate k
    """
    s = s.strip()
    tokens: List[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c in "(),":
            tokens.append(c)
            i += 1
            continue

        j = i
        while j < len(s) and (s[j].isalnum() or s[j] == "_"):
            j += 1
        tok = s[i:j]
        if tok.lower() in ("and", "or"):
            tok = tok.upper()
        tokens.append(tok)
        i = j
    return tokens


# ============================================================
# 3) Parser (recursive descent)
#    precedence: AND > OR
#    threshold gate: (k, expr1, expr2, ...)
# ============================================================
class Parser:
    def __init__(self, tokens: List[str]):
        self.toks = tokens
        self.pos = 0

    def peek(self) -> Optional[str]:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def consume(self, expected: Optional[str] = None) -> str:
        tok = self.peek()
        if tok is None:
            raise ValueError("Unexpected end of input.")
        if expected is not None and tok != expected:
            raise ValueError(f"Expected '{expected}', got '{tok}'.")
        self.pos += 1
        return tok

    def parse(self) -> Node:
        node = self.parse_or()
        if self.peek() is not None:
            raise ValueError(f"Extra tokens remaining: {self.toks[self.pos:]}")
        return node

    def parse_or(self) -> Node:
        node = self.parse_and()
        while self.peek() == "OR":
            self.consume("OR")
            right = self.parse_and()
            node = Gate(kind="OR", k=1, children=[node, right])  # OR = 1-of-2
        return node

    def parse_and(self) -> Node:
        node = self.parse_atom()
        while self.peek() == "AND":
            self.consume("AND")
            right = self.parse_atom()
            node = Gate(kind="AND", k=2, children=[node, right])  # AND = 2-of-2
        return node

    def parse_atom(self) -> Node:
        tok = self.peek()
        if tok == "(":
            # Threshold gate: (k, ...)
            if self._is_threshold_gate():
                return self.parse_threshold_gate()

            # Parenthesized expression
            self.consume("(")
            node = self.parse_or()
            self.consume(")")
            return node

        # Leaf
        if tok is None:
            raise ValueError("Unexpected end. Expected leaf or '('.")
        if tok in {"AND", "OR", ",", ")"}:
            raise ValueError(f"Unexpected token '{tok}' where leaf expected.")
        self.consume()
        return Leaf(tok)

    def _is_threshold_gate(self) -> bool:
        # Pattern: "(" digit ","
        if self.peek() != "(":
            return False
        if self.pos + 2 >= len(self.toks):
            return False
        return self.toks[self.pos + 1].isdigit() and self.toks[self.pos + 2] == ","

    def parse_threshold_gate(self) -> Node:
        self.consume("(")
        k_tok = self.consume()
        if not k_tok.isdigit():
            raise ValueError("Threshold gate: k must be a number.")
        k = int(k_tok)
        self.consume(",")

        children: List[Node] = []
        while True:
            tok = self.peek()
            if tok is None:
                raise ValueError("Unclosed threshold gate. Missing ')'.")
            if tok == ")":
                break
            if tok == ",":
                self.consume(",")
                continue
            child = self.parse_atom()
            children.append(child)

        self.consume(")")
        if not (1 <= k <= len(children)):
            raise ValueError(f"Invalid threshold gate: k={k}, n={len(children)}")
        return Gate(kind="THRESH", k=k, children=children)


def parse_policy(policy_str: str) -> Node:
    tokens = tokenize(policy_str)
    return Parser(tokens).parse()


# ============================================================
# 4) Tree traversal helpers: structure table + Tab II-like table
# ============================================================
def build_structure_table(root: Node):
    """
    Returns rows:
      Subtree, RootName, Leaf nodes (direct leaves), Non-leaf nodes (direct gates), Threshold
    RootName uses: sr for root, then s1,s2,...
    Subtree uses: Tr for root, then T1,T2,...
    """
    internal_name: Dict[int, str] = {}
    internal_nodes: List[Gate] = []
    counter = 1

    def assign_names(node: Node, is_root: bool = False):
        nonlocal counter
        if isinstance(node, Leaf):
            return
        # Gate
        if is_root:
            internal_name[id(node)] = "sr"
        else:
            internal_name[id(node)] = f"s{counter}"
            counter += 1
        internal_nodes.append(node)
        for c in node.children:
            assign_names(c, is_root=False)

    assign_names(root, is_root=True)

    # Subtree labels
    subtree_label: Dict[int, str] = {}
    idx = 1
    for n in internal_nodes:
        if internal_name[id(n)] == "sr":
            subtree_label[id(n)] = "Tr"
        else:
            subtree_label[id(n)] = f"T{idx}"
            idx += 1

    def L_set(node: Gate) -> Set[str]:
        return {c.name for c in node.children if isinstance(c, Leaf)}

    def N_set(node: Gate) -> Set[str]:
        return {internal_name[id(c)] for c in node.children if isinstance(c, Gate)}

    rows = []
    for node in internal_nodes:
        rows.append({
            "Subtree": subtree_label[id(node)],
            "RootName": internal_name[id(node)],
            "Leaf nodes": L_set(node),
            "Non-leaf nodes": N_set(node),
            "Threshold": node.k
        })
    return rows


def build_tab2(root: Node, A: Set[str]):
    """
    Build Tab II-like info for each subtree:
      Subtree | Leaf nodes | Non-leaf nodes | Threshold | Satisfying non-leaf nodes

    "Satisfying non-leaf nodes" means: which direct non-leaf children subtrees are satisfied.
    """
    # Name internal nodes: sr / s1,s2,...
    internal_name: Dict[int, str] = {}
    internal_nodes: List[Gate] = []
    counter = 1

    def assign_names(node: Node, is_root: bool = False):
        nonlocal counter
        if isinstance(node, Leaf):
            return
        if is_root:
            internal_name[id(node)] = "sr"
        else:
            internal_name[id(node)] = f"s{counter}"
            counter += 1
        internal_nodes.append(node)
        for c in node.children:
            assign_names(c, is_root=False)

    assign_names(root, is_root=True)

    # Subtree labels: Tr / T1,T2,...
    subtree_label: Dict[int, str] = {}
    idx = 1
    for n in internal_nodes:
        if internal_name[id(n)] == "sr":
            subtree_label[id(n)] = "Tr"
        else:
            subtree_label[id(n)] = f"T{idx}"
            idx += 1

    def L_set(node: Gate) -> Set[str]:
        return {c.name for c in node.children if isinstance(c, Leaf)}

    def N_set(node: Gate) -> Set[str]:
        return {internal_name[id(c)] for c in node.children if isinstance(c, Gate)}

    # Evaluate satisfaction bottom-up
    satisfied: Dict[int, bool] = {}
    S_sat_nonleaf: Dict[int, Set[str]] = {}

    def eval_satisfied(node: Node) -> bool:
        if isinstance(node, Leaf):
            return node.name in A

        leaf_ok = sum(1 for c in node.children if isinstance(c, Leaf) and c.name in A)
        sat_nonleaf: Set[str] = set()
        nonleaf_ok = 0

        for c in node.children:
            if isinstance(c, Gate):
                child_sat = eval_satisfied(c)
                if child_sat:
                    sat_nonleaf.add(internal_name[id(c)])
                    nonleaf_ok += 1

        ok = (leaf_ok + nonleaf_ok) >= node.k
        satisfied[id(node)] = ok
        S_sat_nonleaf[id(node)] = sat_nonleaf
        return ok

    eval_satisfied(root)

    rows2 = []
    for node in internal_nodes:
        rows2.append({
            "Subtree": subtree_label[id(node)],
            "Leaf nodes": L_set(node),
            "Non-leaf nodes": N_set(node),
            "Threshold": node.k,
            "Satisfying non-leaf nodes": S_sat_nonleaf[id(node)]
        })
    return rows2


# ============================================================
# 5) ThresholdABE (Setup/KeyGen/Encrypt/Decrypt)
# ============================================================
class ThresholdABE:
    def __init__(self, group_obj: PairingGroup, ell: int):
        """
        ell: number of normal attributes |U|
        U = {1..ell}
        U' = {ell+1 .. 2ell-1} (default attributes), size ell-1
        """
        self.group = group_obj
        self.ell = ell
        self.U = list(range(1, ell + 1))
        self.U_prime = list(range(ell + 1, 2 * ell))  # ell-1 elements

    def setup(self):
        g = self.group.random(G1)
        g2 = self.group.random(G2)

        alpha = self.group.random(ZR)
        beta = self.group.random(ZR)
        theta = self.group.random(ZR)

        g1 = g ** alpha
        v = g ** theta
        w = g2 ** (alpha / theta)
        Z = pair(g1, g2)

        # h_0 ... h_{2ℓ-1}
        # need indices up to 2ℓ-1
        h: Dict[int, Any] = {}
        # Allocate extra h-indices to avoid KeyError when a subtree has more non-leaf children
        # than (t_j-1) in practical policies. This keeps the implementation robust.
        # (Original scheme indexes up to 2*ell-1; here we pre-allocate a wider range.)
        max_h = 4 * self.ell
        for i in range(0, max_h + 1):
            h[i] = self.group.random(G2)

        msk = {
            "alpha": alpha,
            "w_1_over_beta": w ** (1 / beta)   # w^(1/beta) in G2
        }
        params = {
            "g": g,
            "g2": g2,
            "Z": Z,
            "h": h,
            "v_beta": v ** beta                # (v^beta) in G1
        }
        return msk, params

    def keygen(self, msk, params, A_idx: Set[int]):
        """
        A_idx ⊆ U is a set of integer indices (attributes owned by the user).
        Secret key also includes all default attributes U'.
        """
        # random polynomial q of degree ℓ-1 with q(0)=alpha
        coeffs = [msk["alpha"]] + [self.group.random(ZR) for _ in range(self.ell - 1)]

        def q(i: int):
            iZ = self.group.init(ZR, i)
            acc = self.group.init(ZR, 0)
            for j, cj in enumerate(coeffs):
                acc += cj * (iZ ** j)
            return acc

        r = self.group.random(ZR)

        # NOTE:
        # In the *original* scheme, SK is generated for i in A ∪ U' (default attributes),
        # where U' = {ell+1 .. 2ell-1}. That guarantees decryption indices (including the
        # "non-leaf" interpolation indices 2ell - t_j + pos) never exceed 2ell-1.
        #
        # In this implementation we intentionally pre-allocated a larger h-index range in
        # Setup (to avoid KeyError in Encrypt for practical policies that may yield indices
        # beyond 2ell-1). To keep Encrypt/Decrypt consistent, we also allow KeyGen to
        # generate SK components for any indices that might appear during decryption.
        #
        # Practically: we generate SK for all i in [1..max_h], so any interpolation set X
        # constructed by Decrypt will have the needed SK[i].
        max_h = max(int(k) for k in params["h"].keys())
        SK: Dict[str, Dict[str, Any]] = {}
        U_all = set(A_idx) | set(self.U_prime) | set(range(1, max_h + 1))
        for i in U_all:
            qi = q(i)

            # a_i = (g2 * h0 * h_i)^{r q(i)}    in G2
            a_i = (params["g2"] * h_get(params, 0) * h_get(params, i)) ** (r * qi)

            # b_i = g^{r q(i)}                  in G1
            b_i = params["g"] ** (r * qi)

            # c_i[j] = h_j^{r q(i)}             in G2, for j != i
            c_i: Dict[str, Any] = {}
            max_h = max(int(k) for k in params["h"].keys())
            for j in range(1, max_h + 1):
                c_i[str(j)] = h_get(params, j) ** (r * qi)

            # d = w^{(r-1)/beta} = (w^(1/beta))^(r-1)  in G2
            d_i = msk["w_1_over_beta"] ** (r - 1)

            SK[str(i)] = {"a": a_i, "b": b_i, "c": c_i, "d": d_i}

        # Debug meta (safe for local testing only): helps validate algebra.
        SK["_meta"] = {"r": r, "alpha": msk["alpha"]}

        return SK

    def encrypt(self, M: GT, params, policy: str):
        policy = normalize_policy(policy)
        root = parse_policy(policy)
        if isinstance(root, Leaf):
            root = Gate(kind="THRESH", k=1, children=[root])

        rows = build_structure_table(root)
        if not rows:
            raise ValueError(f"Invalid/empty policy structure: {policy!r}")

        # rho: leaf attribute name -> index in [1..ell]
        def make_rho_from_policy(rows_):
            attrs: List[str] = []
            for r in rows_:
                for a in sorted(r["Leaf nodes"]):
                    if a not in attrs:
                        attrs.append(a)
            if len(attrs) > self.ell:
                raise ValueError(f"Policy has {len(attrs)} distinct leaf attrs, but ell={self.ell} is too small.")
            return {a: i + 1 for i, a in enumerate(attrs)}

        rho = make_rho_from_policy(rows)

        # sample s-values for each internal node name
        s_map: Dict[str, Any] = {}
        for r in rows:
            s_map[r["RootName"]] = self.group.random(ZR)

        CT_subtrees: Dict[str, Dict[str, Any]] = {}
        # --- FIX: ensure root share exists under key "sr" ---
        root_row = None
        for r in rows:
            if r.get("Subtree") == "Tr":  # 你的代码下面用 Tname=="Tr" 判断 root
                root_row = r
                break
        if root_row is None:
            root_row = rows[0]  # 兜底

        root_rootname = root_row["RootName"]
        if "sr" not in s_map:
            s_map["sr"] = s_map[root_rootname]

        s_r = s_map["sr"]

        for r in rows:
            Tname = r["Subtree"]
            rootName = r["RootName"]
            tj = r["Threshold"]
            sj = s_map[rootName]

            # L_j indices
            Lj = [rho[a] for a in sorted(r["Leaf nodes"])]

            # N_j names (child internal node names) — must match decrypt ordering
            Nj = sorted(list(r["Non-leaf nodes"]))

            # Omega_j = {ell+1 .. 2ell - tj}
            Omega = list(range(self.ell + 1, 2 * self.ell - tj + 1))

            ct: Dict[str, Any] = {}

            # Always include ct1/ct2 (even if Lj empty): ct1 = (h0 * Π_{t∈Lj∪Omega} h_t)^{sj}, ct2 = g^{sj}
            prod = h_get(params, 0)
            for idx in Lj + Omega:
                prod *= h_get(params, idx)
            ct["ct1"] = prod ** sj
            ct["ct2"] = params["g"] ** sj

            # For each child gate in Nj: ct{i+2} = h_{2ell - tj + i}^{sj} * g2^{s_child}
            for i, child_rootName in enumerate(Nj, start=1):
                s_child = s_map[child_rootName]
                h_index = 2 * self.ell - tj + i  # i is 1-based position; scheme uses offset starting at 0
                ct[f"ct{i + 2}"] = (h_get(params, h_index) ** sj) * (params["g2"] ** s_child)

            # Root-only component: ct3 = (v^beta)^{s_r}
            if Tname == "Tr":
                ct["ct_v"] = params["v_beta"] ** s_r

            CT_subtrees[Tname] = ct

        C0 = M * (params["Z"] ** s_r)
        C1 = params["g"] ** s_r

        CT = {
            "C0": C0,
            "C1": C1,
            "ct_T": CT_subtrees,
            "policy": policy,
            "rho": rho,
            "ell": self.ell
        }
        # Debug-only: keep s-values so we can validate decryption math end-to-end.
        CT["_debug"] = {"s_map": s_map}
        return CT

    def decrypt(self, CT, SK, params, A_names: Set[str]):
        """
        Decrypt according to the subtree-based algorithm.
        A_names: user's attribute-name set, e.g., {"attC","attD","attE","attF"}
        """
        policy = CT["policy"]
        root = parse_policy(policy)
        if isinstance(root, Leaf):
            root = Gate(kind="THRESH", k=1, children=[root])

        struct_rows = build_structure_table(root)
        root_to_sub = {r["RootName"]: r["Subtree"] for r in struct_rows}
        struct_map = {r["Subtree"]: r for r in struct_rows}

        tab2 = build_tab2(root, A_names)
        tab_map = {r["Subtree"]: r for r in tab2}

        rho = CT["rho"]
        A_idx = {rho[a] for a in A_names if a in rho}

        # Lagrange coefficient Δ_{i,S}(0)
        def lagrange_coeff(i: int, S: List[int]):
            iZ = self.group.init(ZR, i)
            x0 = self.group.init(ZR, 0)
            num = self.group.init(ZR, 1)
            den = self.group.init(ZR, 1)
            for j in S:
                if j == i:
                    continue
                jZ = self.group.init(ZR, j)
                num *= (x0 - jZ)
                den *= (iZ - jZ)
            return num / den

        def omega_set(tj: int):
            return list(range(self.ell + 1, 2 * self.ell - tj + 1))

        # base_i should be (g2*h0*Π_{t∈Tset} h_t)^{r q(i)}.
        # Note: SK[str(i)]["a"] = (g2*h0*h_i)^{r q(i)} always contains h_i.
        # To avoid erroneously including h_i when i ∉ Tset, we remove it via / c_i[i]
        # and then multiply exactly the h_t factors we need from c_i[t].
        def build_base_i(i: int, Tset: List[int]):
            # (g2*h0)^{r q(i)}
            base = SK[str(i)]["a"] / SK[str(i)]["c"][str(i)]
            for t in Tset:
                base *= SK[str(i)]["c"][str(t)]  # h_t^{r q(i)} (includes t=i only if i in Tset)
            return base

        memo: Dict[str, Any] = {}  # subtree -> (Dj1, Pj2)

        def dec_subtree(Tname: str):
            if Tname in memo:
                return memo[Tname]

            row_struct = struct_map[Tname]
            row_tab = tab_map[Tname]
            tj = row_struct["Threshold"]
            rootName = row_struct["RootName"]

            Lj_names = sorted(list(row_struct["Leaf nodes"]))
            Lj = [rho[a] for a in Lj_names]

            Nj_names = sorted(list(row_struct["Non-leaf nodes"]))  # must match encrypt ordering

            # Satisfied leaves in this subtree
            sat_leaf = [rho[a] for a in Lj_names if a in A_names]

            # NOTE: "Satisfying non-leaf nodes" cannot be precomputed at Encrypt time
            # because it depends on the decryptor's attribute set. During Decrypt, we
            # determine satisfied child subtrees by recursion (Dk1 != None).

            # Recurse on all children gates
            child_info = []  # (pos, child_rootName, child_Tname, Dk1, Pk2)
            for pos, child_rootName in enumerate(Nj_names, start=1):
                child_T = root_to_sub[child_rootName]
                Dk1, Pk2 = dec_subtree(child_T)
                child_info.append((pos, child_rootName, child_T, Dk1, Pk2))

            # Choose A'_j (deterministic: first few satisfied leaves)
            A_prime = sat_leaf[:min(len(sat_leaf), tj)]
            need_nonleaf = max(0, tj - len(A_prime))

            # Choose satisfied non-leaf children in Nj order (deterministic)
            sat_child_pos: List[int] = [pos for (pos, _cr, _ct, Dk1, _Pk2) in child_info if Dk1 is not None]

            # Check satisfaction: |L∩A| + |S| >= t
            if len(sat_leaf) + len(sat_child_pos) < tj:
                memo[Tname] = (None, None)
                return memo[Tname]

            Sj_ordered_pos = sat_child_pos[:need_nonleaf]

            # Indices representing satisfied non-leaf nodes in interpolation:
            # i = 2ell - tj + pos
            S_indices = [2 * self.ell - tj + pos for pos in Sj_ordered_pos]

            Omega = omega_set(tj)

            # Interpolation set X = A' ∪ S_indices ∪ Ω
            X = list(dict.fromkeys(A_prime + S_indices + Omega))

            # Tset used inside base_i product: L ∪ S_indices ∪ Ω
            Tset = list(dict.fromkeys(Lj + S_indices + Omega))

            # Debug: show how this subtree is being satisfied and which indices are used.
            if CT.get("_debug", None) is not None:
                print(f"[DEBUG] {Tname}: t={tj}, sat_leaf={sat_leaf}, sat_child_pos={sat_child_pos}, A'={A_prime}, need_nonleaf={need_nonleaf}, Sj_pos={Sj_ordered_pos}")
                print(f"[DEBUG] {Tname}: S_indices={S_indices}, Omega={Omega}")
                print(f"[DEBUG] {Tname}: X={X}")
                print(f"[DEBUG] {Tname}: Tset={Tset}")

            # Compute Pj1, Pj2
            Pj1 = self.group.init(G2, 1)
            Pj2 = self.group.init(G1, 1)

            for i in X:
                if str(i) not in SK:
                    raise ValueError(f"Missing SK[{i}] needed for interpolation set X")
                delta = lagrange_coeff(i, X)
                Pj1 *= (build_base_i(i, Tset) ** delta)
                Pj2 *= (SK[str(i)]["b"] ** delta)

            ctj = CT["ct_T"][Tname]
            # Charm's pair() expects (G1, G2). Here ct1 is in G2 and Pj2 in G1,
            # so the argument order must be (Pj2, ct1).
            denom = pair(Pj2, ctj["ct1"])

            # Multiply Dj,3 for selected satisfied non-leaf children:
            # Dj,3 = e(ct_{pos+2}, Pk2) / Dk1
            for pos in Sj_ordered_pos:
                _, child_rootName, child_T, Dk1, Pk2 = child_info[pos - 1]
                if Dk1 is None:
                    raise ValueError(f"Child subtree {child_T} not satisfied but appears in S_j")
                ct_child = ctj[f"ct{pos + 2}"]
                # ct_child is in G2 and Pk2 in G1
                Dj3 = pair(Pk2, ct_child) / Dk1
                denom *= Dj3

            # ct2 is in G1 and Pj1 in G2
            Dj1 = pair(ctj["ct2"], Pj1) / denom
            # Debug: verify subtree Dj1 against expected e(g^{s_j}, g2^{r*alpha})
            try:
                dbg = CT.get("_debug", {})
                meta = SK.get("_meta", {})
                if dbg and meta and "s_map" in dbg and rootName in dbg["s_map"]:
                    sj_dbg = dbg["s_map"][rootName]
                    r_val = meta.get("r")
                    alpha_val = meta.get("alpha")
                    if sj_dbg is not None and r_val is not None and alpha_val is not None:
                        expected_sub = pair(params["g"] ** sj_dbg, params["g2"] ** (r_val * alpha_val))
                        if CT.get("_debug", None) is not None:
                            print(f"[DEBUG] {Tname}: Dj1 == expected_sub ?", Dj1 == expected_sub)
            except Exception as e:
                if CT.get("_debug", None) is not None:
                    print(f"[DEBUG] {Tname}: subtree check failed:", repr(e))
            memo[Tname] = (Dj1, Pj2)
            return memo[Tname]

        # Root
        Dr1, _ = dec_subtree("Tr")
        if Dr1 is None:
            raise ValueError("Access policy not satisfied. Decryption failed.")

        # Dr2 = e( (v^beta)^{s_r}, w^{(r-1)/beta} ) = e(ct_Tr['ct3'], d)
        # Pick any numeric i (ignore debug metadata keys)
        any_i = next(k for k in SK.keys() if isinstance(k, str) and k.isdigit())
        Dr2 = pair(CT["ct_T"]["Tr"]["ct_v"], SK[any_i]["d"])

        # Recover message
        M = CT["C0"] * (Dr2 / Dr1)

        # =========================
        # Debug diagnostics
        # =========================
        try:
            dbg = CT.get("_debug", {})
            meta = SK.get("_meta", {})
            if dbg and meta:
                s_r = dbg["s_map"].get("sr")
                r_val = meta.get("r")
                alpha_val = meta.get("alpha")
                if s_r is not None and r_val is not None and alpha_val is not None:
                    expected_Dr1 = pair(params["g"] ** s_r, params["g2"] ** (r_val * alpha_val))
                    print("[DEBUG] Dr1 == expected_Dr1 ?", Dr1 == expected_Dr1)
        except Exception as e:
            print("[DEBUG] diagnostics failed:", repr(e))
        return M


# ============================================================
# 6) Demo
# ============================================================
# (demo removed)
# ============================================================
# 6) Single-gate Policy Update: UPKeyGen + CTUpdate
# ============================================================
# NOTE:
# This section is written to be *drop-in* with the ciphertext format produced by ThresholdABE.encrypt():
#   CT = {C0, C1, ct_T:{Tr,T1,...}, policy, rho, _debug:{s_map}}
# It follows your screenshot formulas for ct updating.
#
# Practical requirement:
#   UPKeyGen needs the random number s_j used by the target subtree T_j in ct_T.
#   In this repo, Encrypt stores them at CT['_debug']['s_map'] keyed by RootName (sr, s1, ...).
#   So you can pass E_T = CT['_debug']['s_map'].

from typing import Tuple


def _make_rho_from_policy(root: Node, ell: int) -> Dict[str, int]:
    """Same rho rule as Encrypt: first-seen unique leaf attrs -> 1..ell."""
    rows = build_structure_table(root)
    attrs: List[str] = []
    for r in rows:
        for a in sorted(r["Leaf nodes"]):
            if a not in attrs:
                attrs.append(a)
    if len(attrs) > ell:
        raise ValueError(f"Policy has {len(attrs)} distinct leaf attrs, but ell={ell} is too small.")
    return {a: i + 1 for i, a in enumerate(attrs)}


def _row_by_subtree(policy_root: Node, subtree_name: str) -> Dict[str, Any]:
    rows = build_structure_table(policy_root)
    for r in rows:
        if r["Subtree"] == subtree_name:
            return r
    raise ValueError(f"Subtree '{subtree_name}' not found in policy.")


def _subtree_base(params: Dict[str, Any], ell: int, rho: Dict[str, int], row: Dict[str, Any]) -> Any:
    """Compute (h0 * Π_{t∈L_j ∪ Ω_j} h_t) in G2 for a subtree row."""
    tj = row["Threshold"]
    Lj = [rho[a] for a in sorted(row["Leaf nodes"])]
    Omega = list(range(ell + 1, 2 * ell - tj + 1))
    prod = h_get(params, 0)
    for idx in Lj + Omega:
        prod *= h_get(params, idx)
    return prod



# --------------------------
# UPKeyGen (single-gate)
# --------------------------

def UPKeyGen(
    group: PairingGroup,
    params: Dict[str, Any],
    ell: int,
    E_T: Dict[str, Any],
    old_policy: str,
    new_policy: str,
    target_subtree: str,
    mode: str,
    # Attributes2New only:
    new_subtree: Optional[str] = None,
    pos_new_gate: Optional[int] = None,
) -> Dict[str, Any]:
    """Generate update key tk_{T->T'} for updating a *single* gate/subtree.

    Inputs
    - E_T: random numbers used in ct_T (pass CT['_debug']['s_map']).
    - target_subtree: subtree label in OLD policy to update (e.g., 'T1').
    - mode: 'Attributes2Existing' or 'Attributes2New'.

    Attributes2Existing output:
      {type, old_policy, new_policy, target_subtree, tprime, tk_j1}

    Attributes2New output additionally includes:
      {new_subtree, pos_new_gate, ct_Tt, tk_leaf}

    Notes
    - This helper assumes you know which subtree is the updated gate (T_j).
    - For Attributes2New, you must provide:
        new_subtree: the NEW gate subtree label (in the NEW policy)
        pos_new_gate: 1-based position among *gate-children* of T_j in the NEW policy
      (this matches the paper index h_{2ℓ-t_j+pos}).
    """

    if mode not in {"Attributes2Existing", "Attributes2New"}:
        raise ValueError("mode must be 'Attributes2Existing' or 'Attributes2New'.")

    old_root = parse_policy(old_policy)
    new_root = parse_policy(new_policy)

    rho_new = _make_rho_from_policy(new_root, ell)

    row_old = _row_by_subtree(old_root, target_subtree)
    row_new = _row_by_subtree(new_root, target_subtree)

    sj = E_T[row_old["RootName"]]  # s_j for the OLD gate (same gate being updated)

    base_old = _subtree_base(params, ell, rho_new, row_old)
    base_new = _subtree_base(params, ell, rho_new, row_new)

    tprime = group.random(ZR)

    # tk_{Tj,1} = (base_new)^{s_j} * (base_old)^{-s_j * t'}
    tk_j1 = (base_new ** sj) * (base_old ** (-sj * tprime))

    if mode == "Attributes2Existing":
        return {
            "type": "Attributes2Existing",
            "old_policy": old_policy,
            "new_policy": new_policy,
            "target_subtree": target_subtree,
            "tprime": tprime,
            "tk_j1": tk_j1,
        }

    # Attributes2New
    if new_subtree is None or pos_new_gate is None:
        raise ValueError("Attributes2New requires new_subtree and pos_new_gate.")

    row_t = _row_by_subtree(new_root, new_subtree)
    st = E_T[row_t["RootName"]]  # s_t for the NEW subtree root

    # Build ct_{Tt} for the new subtree T_t (same as Encrypt, but only for that subtree)
    tj_t = row_t["Threshold"]
    Lj_t = [rho_new[a] for a in sorted(row_t["Leaf nodes"])]
    Nj_t = sorted(list(row_t["Non-leaf nodes"]))
    Omega_t = list(range(ell + 1, 2 * ell - tj_t + 1))

    prod_t = h_get(params, 0)
    for idx in Lj_t + Omega_t:
        prod_t *= h_get(params, idx)

    ct_Tt: Dict[str, Any] = {
        "ct1": prod_t ** st,
        "ct2": params["g"] ** st,
    }

    for i, child_rootName in enumerate(Nj_t, start=1):
        s_child = E_T[child_rootName]
        h_index = 2 * ell - tj_t + i
        ct_Tt[f"ct{i+2}"] = (h_get(params, h_index) ** st) * (params["g2"] ** s_child)

    # tk_leaf = h_{2ℓ - t_j(new) + pos}^{s_j} * g2^{s_t}
    tj_new = row_new["Threshold"]
    h_index_leaf = 2 * ell - tj_new + pos_new_gate
    tk_leaf = (h_get(params, h_index_leaf) ** sj) * (params["g2"] ** st)

    return {
        "type": "Attributes2New",
        "old_policy": old_policy,
        "new_policy": new_policy,
        "target_subtree": target_subtree,
        "new_subtree": new_subtree,
        "pos_new_gate": pos_new_gate,
        "tprime": tprime,
        "tk_j1": tk_j1,
        "ct_Tt": ct_Tt,
        "tk_leaf": tk_leaf,
    }


# --------------------------
# CTUpdate
# --------------------------

def CTUpdate(
    CT: Dict[str, Any],
    tk: Dict[str, Any],
) -> Dict[str, Any]:
    """CTUpdate(mpk, ct_T, tk_{T->T'}) -> ct_{T'}

    Implements your screenshot equations.

    For Attributes2Existing:
      ct'_{Tj} = ( ct1^{t'} * tk_j1, ct2, {ct{i+2}} )

    For Attributes2New:
      ct'_{Tj} = ( ct1^{t'} * tk_j1, ct2, {ct{i+2}}, tk_leaf )
      and we also add the new subtree ciphertext ct_{Tt}.

    This function returns a *new* ciphertext dict CT' with:
      - policy replaced by tk['new_policy']
      - rho rebuilt from the new policy
      - ct_T updated for the target subtree (and possibly adds new_subtree)

    NOTE:
      This implementation updates only the affected subtree ciphertext components,
      matching the paper's local update description for a single gate.
    """

    if tk["type"] not in {"Attributes2Existing", "Attributes2New"}:
        raise ValueError("Unknown update key type.")

    # IMPORTANT:
    # Do NOT use deepcopy() here. Charm-Crypto pairing.Element objects are not picklable,
    # which can trigger: TypeError: cannot pickle 'pairing.Element' object.
    # We only need a *structural* copy of the dicts so we can replace a few fields.
    CTp = dict(CT)
    CTp["ct_T"] = dict(CT.get("ct_T", {}))

    # Update policy + rho
    new_policy = tk["new_policy"]
    new_root = parse_policy(new_policy)
    # ell should come from system parameter (stored in CT at Encrypt time)
    ell = CT.get("ell", None)
    if ell is None:
        # fallback for legacy ciphertexts
        ell = max(CT["rho"].values()) if CT.get("rho") else 0
    CTp["ell"] = ell
    CTp["policy"] = new_policy
    CTp["rho"] = _make_rho_from_policy(new_root, ell)

    Tj = tk["target_subtree"]
    if Tj not in CTp["ct_T"]:
        raise ValueError(f"Target subtree '{Tj}' not found in ciphertext.")

    ctj_old = CT["ct_T"][Tj]

    # ct1' = ct1^{t'} * tk_j1
    ct1_new = (ctj_old["ct1"] ** tk["tprime"]) * tk["tk_j1"]

    # keep ct2 and existing ct{i+2}
    ctj_new = {k: v for k, v in ctj_old.items() if k != "ct1"}
    ctj_new["ct1"] = ct1_new

    if tk["type"] == "Attributes2New":
        # append new leaf-node component as a new ct component
        # (paper denotes it as tk_{j,(|Nj|+1)+2}; we store it as 'ct_new_leaf')
        ctj_new["ct_new_leaf"] = tk["tk_leaf"]

        # add new subtree ciphertext
        new_subtree = tk["new_subtree"]
        CTp["ct_T"][new_subtree] = tk["ct_Tt"]

    CTp["ct_T"][Tj] = ctj_new

    # remove debug (optional)
    # CTp.pop('_debug', None)

    return CTp


# ============================================================
# 7) Minimal demo: Encrypt -> UPKeyGen -> CTUpdate
# ============================================================
# (demo removed)


# ============================================================
# 5) Factory: build group + ABE instance
# ============================================================

def build_abe(curve: str = "SS512", ell: int = 10):
    """Create pairing group + your full ThresholdABE instance."""
    group = PairingGroup(curve)
    abe = ThresholdABE(group, ell=ell)
    return group, abe


# ============================================================
# 6) TA CLI utilities (run locally)
# ============================================================

def cmd_setup(args: argparse.Namespace) -> None:
    group, abe = build_abe(args.curve, args.ell)
    msk, mpk = abe.setup()   # in this scheme: (msk, params/mpk)
    out = {
        "curve": args.curve,
        "ell": args.ell,
        "mpk": serialize_any(group, mpk),
        "msk": serialize_any(group, msk),
    }
    save_json(args.out, out)
    print(f"[TA] Setup OK -> wrote: {args.out}")


def _derive_rho_from_policy(policy: str, ell: int) -> Dict[str, int]:
    root = parse_policy(policy)
    rows = build_structure_table(root)
    attrs: List[str] = []
    for r in rows:
        for a in sorted(r["Leaf nodes"]):
            if a not in attrs:
                attrs.append(a)
    if len(attrs) > ell:
        raise ValueError(f"Policy has {len(attrs)} distinct leaf attrs, but ell={ell} is too small.")
    return {a: i + 1 for i, a in enumerate(attrs)}


def cmd_keygen(args: argparse.Namespace) -> None:
    blob = load_json(args.inp)
    group, abe = build_abe(blob["curve"], blob["ell"])
    mpk = deserialize_any(group, blob["mpk"])
    msk = deserialize_any(group, blob["msk"])

    # attrs can be:
    #  - names that appear in a policy (recommended): use --policy to map names -> indices via rho
    #  - or numeric indices directly: e.g. "1,2,3"
    raw = [x.strip() for x in args.attrs.split(",") if x.strip()]
    if args.policy:
        rho = _derive_rho_from_policy(args.policy, blob["ell"])
        A_idx = {rho[a] for a in raw if a in rho}
        missing = [a for a in raw if a not in rho]
        if missing:
            print(f"[TA] Warning: attrs not in policy rho mapping and will be ignored: {missing}")
    else:
        # try numeric indices
        try:
            A_idx = {int(x) for x in raw}
        except Exception:
            raise ValueError("If you don't pass --policy, --attrs must be numeric indices like '1,2,3'.")

    sk = abe.keygen(msk, mpk, A_idx)

    out = {
        "curve": blob["curve"],
        "ell": blob["ell"],
        "attrs": raw,
        "policy": args.policy,
        "sk": serialize_any(group, sk),
    }
    save_json(args.out, out)
    print(f"[TA] KeyGen OK -> wrote: {args.out}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_setup = sub.add_parser("setup", help="TA: Setup() -> mpk,msk")
    ap_setup.add_argument("--curve", default="SS512")
    ap_setup.add_argument("--ell", type=int, default=10)
    ap_setup.add_argument("--out", default="keys/ta_setup.json")
    ap_setup.set_defaults(func=cmd_setup)

    ap_kg = sub.add_parser("keygen", help="TA: KeyGen(msk,A) -> sk_A")
    ap_kg.add_argument("--inp", default="keys/ta_setup.json", help="TA setup json containing mpk+msk")
    ap_kg.add_argument("--attrs", required=True, help='Comma attrs. If you pass --policy, these are names; otherwise numeric indices.')
    ap_kg.add_argument("--policy", default="", help="(Recommended) policy string used to derive rho name->index mapping.")
    ap_kg.add_argument("--out", default="keys/user_sk.json")
    ap_kg.set_defaults(func=cmd_keygen)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
