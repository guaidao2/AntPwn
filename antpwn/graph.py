"""AntPwn v1.2: 决策树即蚁群决策, 蚁群走能力 DAG
====================================================================
架构 (ant policy = decision tree, colony search space = capability DAG):

  DAG 节点 = 能力 (capability)
      rip_control  完全控制返回地址 (session 域, 附带 offset)
      libc_base    当前进程的 libc 基址 (process 域, 随 ASLR 变)
      fmt_k        格式化字符串参数位置 (session 域)
      heap_layout  堆布局/精确 chunk 地址 (session 域)
      write_prim   任意写原语 (process 域)
      shell        终极目标

  DAG 边 = 技术 (Technique)
      requires -> provides, 附带 feasible() 谓词 (决策树的确定性分支)
      和 execute() 执行体 (可能部分成功: 能力入黑板)

  决策树 (DecisionTree) = 蚂蚁在节点处的策略
      特征 = 观测证据 (漏洞类型/保护/gadget/已获能力/崩溃寄存器)
      确定性分支过滤掉不可行边; 证据不足以定序时按边信息素轮盘赌

  蚁群 (Colony) = 多只蚂蚁依次走 DAG
      每只蚂蚁 = 一次完整利用尝试 (一条根->shell 的路径)
      失败蚂蚁的 session 域能力留在黑板, 下一只从检查点续走
      边信息素按 "新获得能力数 + 是否 shell" 沉积, 蒸发保持探索
      信息素按二进制特征向量持久化到 antpwn_pheromone.json
      -> 跨目标复用: 决策树被蚁群经验"诱导"出来
"""
import json
import os
import random
import time

from . import i18n

# ------------------------------------------------------------------ caps
SESSION = "session"    # valid across processes (offset, fmt_k, ...)
PROCESS = "process"    # valid only inside the live tube (libc_base, ...)

CAP_RIP = "rip_control"
CAP_LIBC = "libc_base"
CAP_FMTK = "fmt_k"
CAP_HEAP = "heap_layout"
CAP_WRITE = "write_prim"
CAP_SHELL = "shell"


class Technique:
    """one edge in the capability DAG"""

    def __init__(self, name, requires, provides, execute,
                 feasible=None, scope=SESSION, prio=5, zh="", en="",
                 preamble=None):
        self.name = name
        self.requires = set(requires)
        self.provides = set(provides)
        self.execute = execute            # fn(ctx) -> bool
        self.feasible = feasible or (lambda ctx: True)
        self.scope = scope               # scope of provided capabilities
        self.prio = prio                 # expert prior; pheromone overrides
        self.zh, self.en = zh, en
        self.preamble = preamble         # input-stream variant this edge lives in
        self.wins = 0                    # lifetime stats (per feature sig)
        self.tries = 0


# ------------------------------------------------------------------ tree
class DecisionTree:
    """the ant's policy: deterministic splits on observed evidence.

    Splits are predicates over the context (binary features + acquired
    capabilities); leaves rank candidate edges. Edges passing every
    split are 'certified'; among certified edges the order comes from
    pheromone (win-rate) — the stochastic part only where evidence
    cannot decide. Leaf visit stats double as pheromone deposit sites.
    """

    # feature extractors: (name, fn(ctx) -> bool)
    FEATURES = [
        ("bof",     lambda c: "bof" in c.vuln_kinds),
        ("fmt",     lambda c: "fmt" in c.vuln_kinds),
        ("heap",    lambda c: "heap" in c.vuln_kinds),
        ("backdoor", lambda c: "backdoor" in c.vuln_kinds),
        ("binsh",   lambda c: c.has_binsh),
        ("pie",     lambda c: c.elf.is_pie),
        ("canary",  lambda c: c.elf.canary),
        ("gadgets", lambda c: c.has_rop_gadgets),
        ("leak_fn", lambda c: c.has_leak_function),
        ("arch32",  lambda c: getattr(c.elf, "bits", 64) == 32),
    ]

    def features(self, ctx):
        f = {}
        for name, fn in self.FEATURES:
            try:
                f[name] = bool(fn(ctx))
            except Exception:
                f[name] = False
        # acquired capabilities act as extra splits (checkpoint routing)
        f["caps"] = frozenset(ctx.capabilities)
        return f

    def certified(self, ctx, edges):
        """deterministic branch: hard preconditions + feature gates.
        This is the decision tree; each feasible() is a split predicate.
        Edges whose provides are ALL already held are goals achieved —
        they leave the candidate set (no redundant re-execution)."""
        return [e for e in edges
                if e.requires <= ctx.capabilities and e.feasible(ctx)
                and not e.provides <= ctx.capabilities]


# ------------------------------------------------------------------ colony
class Colony:
    """ants walk the capability DAG; blackboard carries checkpoints"""

    def __init__(self, edges, log, phero_path="antpwn_pheromone.json", enabled=True):
        self.edges = edges
        self.tree = DecisionTree()
        self.log = log
        self.phero_path = phero_path
        self.enabled = enabled
        self.stats = {}          # feature_sig -> {edge_name: [wins, tries]}
        if self.enabled:
            self._load()

    # ---------------- persistence ----------------
    def _sig(self, ctx):
        f = self.tree.features(ctx)
        return json.dumps({k: (sorted(v) if isinstance(v, frozenset) else v)
                           for k, v in f.items() if k != "caps"},
                          sort_keys=True)

    def _load(self):
        if not os.path.exists(self.phero_path):
            return
        try:
            with open(self.phero_path) as fh:
                self.stats = json.load(fh)
        except Exception:
            self.stats = {}

    def _save(self):
        if not self.enabled:
            return
        try:
            with open(self.phero_path, "w") as fh:
                json.dump(self.stats, fh, indent=1)
        except OSError:
            pass

    def edge_report(self, ctx):
        """wins/tries of every edge for this binary's signature (for reports)."""
        sig = self._sig(ctx)
        return {name: {"wins": w, "tries": t}
                for name, (w, t) in self.stats.get(sig, {}).items()}

    def _edge_stats(self, sig, name):
        d = self.stats.setdefault(sig, {})
        return d.setdefault(name, [0, 0])   # [wins, tries]

    # ---------------- walking ----------------
    def choose(self, ctx, cands):
        """decision tree certifies; pheromone (experience) overrides the
        expert prior when enough evidence has accumulated"""
        if not cands:
            return None
        if len(cands) == 1:
            return cands[0]
        sig = self._sig(ctx)
        scored = []
        for e in cands:
            w, t = self._edge_stats(sig, e.name)
            conf = t / (t + 3.0)                 # experience weight
            phero = (w + 0.25) / (t + 0.5)       # smoothed win-rate
            prior = 1.0 / (1.0 + e.prio)
            scored.append((conf * phero + (1 - conf) * prior, e.prio, e))
        scored.sort(key=lambda x: (-x[0], x[1]))
        # epsilon-greedy exploration over the tree's ranking
        if random.random() < 0.1:
            return random.choice(cands)
        return scored[0][2]

    def walk(self, ctx, budget=14):
        """one ant: root -> (shell | dead-end). Returns (trail, ok)."""
        trail = []
        session_gained = []
        failed_local = set()      # each edge at most once per ant
        for _ in range(budget):
            if CAP_SHELL in ctx.capabilities:
                break
            cands = [e for e in self.tree.certified(ctx, self.edges)
                     if e not in failed_local]
            edge = self.choose(ctx, cands)
            if edge is None:
                break    # dead end: nothing certified left
            zh = edge.zh if i18n.LANG == "zh" else edge.en
            self.log.log("TREE", f"  -> {edge.name}: {zh}")
            # switch to this edge's input-stream semantics: the offset is
            # preamble-relative in multi-read programs
            offs = getattr(ctx, "offsets_map", None)
            if offs:
                ctx.offset = offs.get(edge.preamble or b"", ctx.offset)
            ok = False
            try:
                ok = edge.execute(ctx)
            except Exception:
                ok = False
            trail.append((edge, ok))
            sig = self._sig(ctx)
            st = self._edge_stats(sig, edge.name)
            st[1] += 1
            if ok:
                st[0] += 1
                for cap in edge.provides:
                    if cap not in ctx.capabilities:
                        ctx.capabilities.add(cap)
                        if edge.scope == SESSION:
                            session_gained.append(cap)
            else:
                failed_local.add(edge)   # tries++ already lowers win-rate
        return trail, CAP_SHELL in ctx.capabilities, session_gained

    def solve(self, ctx, waves=4, ants_per_wave=2):
        """colony: waves of ants, blackboard checkpointing between ants"""
        base_session = set()
        for w in range(waves):
            for k in range(ants_per_wave):
                # fresh process-scoped caps (ASLR), session caps persist
                ctx.capabilities = set(base_session)
                ctx.live = {}
                self.log.log("COLONY",
                             f"wave{w} ant{k}: caps={sorted(ctx.capabilities) or ['-']}")
                trail, ok, gained = self.walk(ctx)
                base_session |= set(gained)
                if ok:
                    self._save()
                    return trail, True
        self._save()
        return None, False


def record_edge(ctx, edge_name, win=True, phero_path="antpwn_pheromone.json"):
    """Record one pheromone observation without running the whole colony.

    Used by the gdb plugin: an offset recovered from a real crash inside gdb is
    evidence worth keeping for the next run (`dt-offset`), and it shares the
    same signature bucket as the CLI so both learn from each other.
    """
    stats = {}
    try:
        if os.path.exists(phero_path):
            with open(phero_path) as fh:
                stats = json.load(fh)
    except Exception:
        stats = {}
    features = DecisionTree().features(ctx)
    sig = json.dumps({k: (sorted(v) if isinstance(v, frozenset) else v)
                      for k, v in features.items() if k != "caps"},
                     sort_keys=True)
    slot = stats.setdefault(sig, {}).setdefault(edge_name, [0, 0])
    slot[1] += 1
    if win:
        slot[0] += 1
    try:
        with open(phero_path, "w") as fh:
            json.dump(stats, fh, indent=1)
    except OSError:
        pass
    return slot
