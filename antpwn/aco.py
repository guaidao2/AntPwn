"""AntPwn ACO: Ant Colony Optimization for exploit-parameter search
蚁群算法: 用信息素引导蚂蚁在"参数空间"搜索 (溢出偏移/格式化字符串偏移/堆布局),
目标函数由动态验证器反馈 (crash-距离 / 寄存器控制度), 收敛后输出最优解
"""
import random


class Ant:
    def __init__(self, pid):
        self.id = pid
        self.trail = []      # chosen value per dimension
        self.score = 0.0


class AntColony:
    """generic ACO over discrete candidate values per dimension.

    dims: list of candidate lists, e.g. [range(64,192), range(1,40)]
    fitness(trail) -> float in [0,1]; 1 = perfect (shell)
    """

    def __init__(self, dims, fitness, ants=24, iters=30,
                 evap=0.35, alpha=1.0, beta=2.0, seed=None):
        self.dims = dims
        self.fitness = fitness
        self.n_ants, self.iters = ants, iters
        self.evap, self.alpha, self.beta = evap, alpha, beta
        self.rng = random.Random(seed)
        # pheromone matrix per dimension
        self.tau = [[1.0] * len(c) for c in dims]
        # neutral heuristic: no prior preference among candidates
        self.heuristic = [[1.0] * len(c) for c in dims]
        self.best = None
        self.best_score = -1
        self.history = []

    def _choose(self, d):
        weights = [self.tau[d][i] ** self.alpha * self.heuristic[d][i] ** self.beta
                   for i in range(len(self.dims[d]))]
        return self.rng.choices(range(len(weights)), weights=weights)[0]

    def _deposit(self, ant, amount):
        for d, idx in enumerate(ant.trail):
            self.tau[d][idx] += amount

    def run(self, on_iter=None):
        for it in range(self.iters):
            # evaporate
            for row in self.tau:
                for i in range(len(row)):
                    row[i] *= (1 - self.evap)
            ants = []
            for k in range(self.n_ants):
                a = Ant(k)
                a.trail = [self._choose(d) for d in range(len(self.dims))]
                vals = [self.dims[d][i] for d, i in enumerate(a.trail)]
                a.score = self.fitness(vals)
                ants.append(a)
                if a.score > self.best_score:
                    self.best_score = a.score
                    self.best = vals
                    if on_iter:
                        on_iter(it, k, vals, a.score)
                if a.score >= 1.0:
                    # elite fast-stop
                    self._deposit(a, 5.0)
                    return vals, a.score
            # deposit by rank
            ants.sort(key=lambda x: -x.score)
            for rank, a in enumerate(ants[:max(1, self.n_ants // 4)]):
                self._deposit(a, 2.0 / (1 + rank))
            self.history.append(self.best_score)
            if on_iter:
                on_iter(it, -1, self.best, self.best_score)
            # convergence check
            if it > 6 and self.history[-1] == self.history[-6] and self.best_score > 0.95:
                break
            if it > 10 and len(set(self.history[-8:])) == 1 and self.best_score > 0:
                break
        return self.best, self.best_score


class OffsetColony(AntColony):
    """specialized: search stack-overflow offset to saved RIP.

    fitness: run target with cyclic-ish payload of given offset; measure
    how much control we have over RIP (via debug crash regs).
    """

    def __init__(self, make_payload, check, lo=64, hi=200, step=8, **kw):
        dims = [list(range(lo, hi, step))]
        super().__init__(dims, self._fit, **kw)
        self.make_payload, self.check = make_payload, check
        self.probes = 0

    def _fit(self, vals):
        off = vals[0]
        self.probes += 1
        return self.check(off)
