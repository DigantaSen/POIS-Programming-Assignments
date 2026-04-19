import {
  FoundationId,
  PrimitiveId,
  PrimitiveOracle,
  ProofSummary,
  ReductionStep,
  ReductionTraceItem,
  normalizeHex,
  primitiveLabel,
  primitiveDuePa,
  stubHex,
} from "./domain";

const REDUCTION_EDGES: ReductionStep[] = [
  {
    from: "OWP",
    to: "OWF",
    functionApplied: "Interpret permutation inverter as OWF inverter",
    theorem: "Any one-way permutation is a one-way function",
    security: "If OWF is broken with advantage eps, OWP breaks with eps' >= eps.",
    pa: "PA01",
    implemented: true,
  },
  {
    from: "OWF",
    to: "PRG",
    functionApplied: "HILL-style hard-core expansion",
    theorem: "OWF implies PRG (hard-core bit + expansion)",
    security: "Adv_PRG(D) <= poly(n) * Adv_OWF(B).",
    pa: "PA01",
    implemented: true,
  },
  {
    from: "PRG",
    to: "PRF",
    functionApplied: "GGM tree construction",
    theorem: "PRG implies PRF",
    security: "Adv_PRF(A) <= q * Adv_PRG(B).",
    pa: "PA02",
    implemented: true,
  },
  {
    from: "PRF",
    to: "PRP",
    functionApplied: "Feistel/Luby-Rackoff lifting",
    theorem: "PRF implies PRP under standard rounds",
    security: "Adv_PRP(A) <= Adv_PRF(B) + O(q^2 / 2^n).",
    pa: "PA04",
    implemented: false,
    duePa: "PA04",
  },
  {
    from: "PRF",
    to: "MAC",
    functionApplied: "Tag m with F_k(m)",
    theorem: "PRF security implies existentially unforgeable MAC",
    security: "Adv_MAC(F) <= Adv_PRF(D) + q/2^n.",
    pa: "PA05",
    implemented: false,
    duePa: "PA05",
  },
  {
    from: "PRF",
    to: "ENC",
    functionApplied: "Use PRF output as stream keystream",
    theorem: "PRF-based stream construction is IND-CPA secure",
    security: "Adv_IND-CPA(A) <= Adv_PRF(D).",
    pa: "PA03",
    implemented: true,
  },
  {
    from: "PRF",
    to: "CRHF",
    functionApplied: "Domain-fixed keyed hashing",
    theorem: "PRF can instantiate collision-resistant family in toy model",
    security: "Collision finder implies PRF distinguisher with related advantage.",
    pa: "PA08",
    implemented: false,
    duePa: "PA08",
  },
  {
    from: "MAC",
    to: "PRF",
    functionApplied: "Query MAC oracle as keyed function oracle",
    theorem: "MAC forger can be used in PRF distinguishing game",
    security: "Adv_PRF(D) >= Adv_MAC(F) / q.",
    pa: "PA05",
    implemented: false,
    duePa: "PA05",
    note: "Reverse-direction reduction used in backward mode demos.",
  },
  {
    from: "ENC",
    to: "PRF",
    functionApplied: "Lift IND-CPA adversary into PRF distinguisher",
    theorem: "Stream-ENC security reduces to PRF security",
    security: "Adv_PRF(D) >= Adv_IND-CPA(A).",
    pa: "PA03",
    implemented: true,
  },
  {
    from: "PRP",
    to: "PRF",
    functionApplied: "Apply PRP switching lemma",
    theorem: "Strong PRP implies PRF on distinct queries",
    security: "Adv_PRF(A) <= Adv_PRP(B) + O(q^2 / 2^n).",
    pa: "PA04",
    implemented: false,
    duePa: "PA04",
  },
];

function buildAdjacency(foundation: FoundationId): Map<PrimitiveId, ReductionStep[]> {
  const map = new Map<PrimitiveId, ReductionStep[]>();

  for (const edge of REDUCTION_EDGES) {
    if (foundation === "AES" && edge.from === "OWP") {
      continue;
    }

    const list = map.get(edge.from) ?? [];
    list.push(edge);
    map.set(edge.from, list);
  }

  return map;
}

function reconstructPath(
  prevNode: Map<PrimitiveId, PrimitiveId>,
  prevEdge: Map<PrimitiveId, ReductionStep>,
  source: PrimitiveId,
  target: PrimitiveId,
): ReductionStep[] {
  const route: ReductionStep[] = [];
  let current: PrimitiveId | undefined = target;

  while (current && current !== source) {
    const edge = prevEdge.get(current);
    const parent = prevNode.get(current);
    if (!edge || !parent) {
      return [];
    }
    route.push(edge);
    current = parent;
  }

  route.reverse();
  return route;
}

export function reduce(
  source: PrimitiveId,
  target: PrimitiveId,
  foundation: FoundationId,
): ReductionStep[] | null {
  if (source === target) {
    return [];
  }

  const adjacency = buildAdjacency(foundation);
  const queue: PrimitiveId[] = [source];
  const visited = new Set<PrimitiveId>([source]);
  const prevNode = new Map<PrimitiveId, PrimitiveId>();
  const prevEdge = new Map<PrimitiveId, ReductionStep>();

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) {
      break;
    }

    if (current === target) {
      const route = reconstructPath(prevNode, prevEdge, source, target);
      return route.length === 0 ? null : route;
    }

    const edges = adjacency.get(current) ?? [];
    for (const edge of edges) {
      if (visited.has(edge.to)) {
        continue;
      }
      visited.add(edge.to);
      prevNode.set(edge.to, current);
      prevEdge.set(edge.to, edge);
      queue.push(edge.to);
    }
  }

  return null;
}

export function findReverseHint(
  source: PrimitiveId,
  target: PrimitiveId,
  foundation: FoundationId,
): string | null {
  const backwardRoute = reduce(target, source, foundation);
  if (!backwardRoute) {
    return null;
  }
  return `No direct ${source} -> ${target} path. Try Backward mode to use ${target} -> ${source}.`;
}

export function runReductionTrace(
  sourceOracle: PrimitiveOracle,
  route: ReductionStep[],
  messageHex: string,
  keyHex: string,
  foundation: FoundationId,
): ReductionTraceItem[] {
  const traces: ReductionTraceItem[] = [];
  let currentOracle = sourceOracle;
  let currentInput = normalizeHex(messageHex, "00");

  for (const step of route) {
    const prevOracle = currentOracle;
    const oracleResponseHex = prevOracle.evaluate(currentInput);
    const outputHex = stubHex(
      `${foundation}|reduce|${step.from}|${step.to}|${oracleResponseHex}|${normalizeHex(keyHex, "00")}`,
      16,
    );

    traces.push({
      ...step,
      inputHex: currentInput,
      oracleResponseHex,
      outputHex,
    });

    currentOracle = {
      primitive: step.to,
      evaluate: (queryHex: string) => {
        const answer = prevOracle.evaluate(normalizeHex(queryHex, "00"));
        return stubHex(
          `${foundation}|oracle|${step.from}|${step.to}|${answer}|${normalizeHex(keyHex, "00")}`,
          16,
        );
      },
    };

    currentInput = outputHex;
  }

  return traces;
}

export function buildProofSummary(
  source: PrimitiveId,
  target: PrimitiveId,
  route: ReductionStep[] | null,
): ProofSummary {
  if (source === target) {
    return {
      headline: `${source} and ${target} are identical`,
      detail: "No reduction needed. Identity oracle is used.",
      steps: [
        {
          theorem: "Identity mapping",
          security: "eps' = eps",
          pa: primitiveDuePa[source],
          implemented: false,
          duePa: primitiveDuePa[source],
        },
      ],
    };
  }

  if (!route) {
    return {
      headline: `No direct path from ${source} to ${target}`,
      detail:
        "Selected direction has no route in the current reduction table. Use the mode toggle to attempt the reverse chain.",
      steps: [
        {
          theorem: "Direction unsupported in current table",
          security: "No direct reduction in this direction; try reverse mode",
          pa: primitiveDuePa[target],
          implemented: false,
          duePa: primitiveDuePa[target],
        },
      ],
    };
  }

  return {
    headline: `${primitiveLabel[source]} to ${primitiveLabel[target]}`,
    detail:
      "If an adversary breaks the target with advantage eps, each theorem step lifts it to a breaker for the previous primitive with eps' >= eps / q.",
    steps: route.map((step) => ({
      theorem: step.theorem,
      security: step.security,
      pa: step.pa,
      implemented: step.implemented,
      duePa: step.duePa,
    })),
  };
}
