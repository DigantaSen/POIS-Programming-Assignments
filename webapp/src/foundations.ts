import {
  BuildInputs,
  BuildResult,
  FoundationId,
  PrimitiveExecution,
  PrimitiveId,
  PrimitiveOracle,
  ReductionStep,
  normalizeHex,
  primitiveDuePa,
  stubHex,
} from "./domain";
import { reduce } from "./routing";

export interface FoundationModule {
  id: FoundationId;
  name: string;
  capabilities: PrimitiveId[];
  asOWF: (inputs: BuildInputs) => PrimitiveExecution;
  asPRF: (inputs: BuildInputs) => PrimitiveExecution | null;
  asPRP: (inputs: BuildInputs) => PrimitiveExecution | null;
  asOWP: (inputs: BuildInputs) => PrimitiveExecution | null;
}

function makeExecution(
  primitive: PrimitiveId,
  functionApplied: string,
  theorem: string,
  security: string,
  pa: string,
  implemented: boolean,
  inputs: BuildInputs,
  seedSuffix: string,
): PrimitiveExecution {
  const inputHex = normalizeHex(inputs.messageHex, "00");
  const keyHex = normalizeHex(inputs.keyHex, "00");
  return {
    primitive,
    functionApplied,
    inputHex,
    outputHex: stubHex(`${seedSuffix}|${inputHex}|${keyHex}|${primitive}`, 16),
    theorem,
    security,
    pa,
    implemented,
    duePa: implemented ? undefined : primitiveDuePa[primitive],
  };
}

const aesFoundation: FoundationModule = {
  id: "AES",
  name: "AESFoundation",
  capabilities: ["OWF", "PRF", "PRP"],
  asOWF: (inputs) =>
    makeExecution(
      "OWF",
      "AESFoundation.asOWF(seed, x)",
      "AES family as computational OWF candidate",
      "Stub: modeled as deterministic one-way mapping",
      "PA02",
      false,
      inputs,
      "aes-as-owf",
    ),
  asPRF: (inputs) =>
    makeExecution(
      "PRF",
      "AESFoundation.asPRF(k, x)",
      "PRF assumption for keyed AES-like family",
      "Stub: Adv_PRF(A) bounded by Adv_AES(A)",
      "PA02",
      false,
      inputs,
      "aes-as-prf",
    ),
  asPRP: (inputs) =>
    makeExecution(
      "PRP",
      "AESFoundation.asPRP(k, x)",
      "PRP assumption for keyed permutation family",
      "Stub: Adv_PRP(A) bounded by Adv_AES(A)",
      "PA02",
      false,
      inputs,
      "aes-as-prp",
    ),
  asOWP: () => null,
};

const dlpFoundation: FoundationModule = {
  id: "DLP",
  name: "DLPFoundation",
  capabilities: ["OWF", "OWP"],
  asOWF: (inputs) =>
    makeExecution(
      "OWF",
      "DLPFoundation.asOWF(g, x)",
      "Discrete-log hardness implies OWF hardness",
      "Solver for OWF yields DLP solver",
      "PA01",
      true,
      inputs,
      "dlp-as-owf",
    ),
  asOWP: (inputs) =>
    makeExecution(
      "OWP",
      "DLPFoundation.asOWP(g, x)",
      "Exponentiation over prime-order group as OWP",
      "Inverter for permutation yields DLP solver",
      "PA01",
      true,
      inputs,
      "dlp-as-owp",
    ),
  asPRF: () => null,
  asPRP: () => null,
};

function executeFoundationCapability(
  foundation: FoundationModule,
  capability: PrimitiveId,
  inputs: BuildInputs,
): PrimitiveExecution | null {
  if (capability === "OWF") {
    return foundation.asOWF(inputs);
  }
  if (capability === "PRF") {
    return foundation.asPRF(inputs);
  }
  if (capability === "PRP") {
    return foundation.asPRP(inputs);
  }
  if (capability === "OWP") {
    return foundation.asOWP(inputs);
  }
  return null;
}

function transformByReduction(stepSeed: string, inputHex: string, keyHex: string): string {
  return stubHex(`${stepSeed}|${normalizeHex(inputHex, "00")}|${normalizeHex(keyHex, "00")}`, 16);
}

function makePlaceholderStep(
  foundationName: string,
  target: PrimitiveId,
  inputs: BuildInputs,
  note: string,
): PrimitiveExecution {
  const inputHex = normalizeHex(inputs.messageHex, "00");
  return {
    primitive: target,
    functionApplied: `${foundationName} -> ${target} (placeholder)`,
    inputHex,
    outputHex: stubHex(`placeholder|${foundationName}|${target}|${inputHex}`, 16),
    theorem: "Route missing in current foundation/reduction table",
    security: "No direct proof in this direction yet",
    pa: primitiveDuePa[target],
    implemented: false,
    duePa: primitiveDuePa[target],
    note,
  };
}

function pickBestCapability(
  foundation: FoundationModule,
  target: PrimitiveId,
  foundationId: FoundationId,
): { capability: PrimitiveId; route: ReductionStep[] } | null {
  let best: { capability: PrimitiveId; route: ReductionStep[] } | null = null;

  for (const capability of foundation.capabilities) {
    const route = reduce(capability, target, foundationId);
    if (!route) {
      continue;
    }

    if (!best || route.length < best.route.length) {
      best = { capability, route };
    }
  }

  return best;
}

function composeOracle(
  foundation: FoundationModule,
  capability: PrimitiveId,
  route: ReductionStep[],
  keyHex: string,
): PrimitiveOracle {
  const capabilityOracle: PrimitiveOracle = {
    primitive: capability,
    evaluate: (queryHex: string) => {
      const execution = executeFoundationCapability(foundation, capability, {
        keyHex,
        messageHex: normalizeHex(queryHex, "00"),
      });
      if (!execution) {
        return stubHex(`missing-capability|${foundation.id}|${capability}`, 16);
      }
      return execution.outputHex;
    },
  };

  let currentOracle = capabilityOracle;
  for (const step of route) {
    const prevOracle = currentOracle;
    currentOracle = {
      primitive: step.to,
      evaluate: (queryHex: string) => {
        const prevOutput = prevOracle.evaluate(queryHex);
        return transformByReduction(
          `${foundation.id}|${step.from}|${step.to}|${step.functionApplied}`,
          prevOutput,
          keyHex,
        );
      },
    };
  }

  return currentOracle;
}

export function getFoundationModule(id: FoundationId): FoundationModule {
  return id === "AES" ? aesFoundation : dlpFoundation;
}

export function buildFromFoundation(
  foundationId: FoundationId,
  target: PrimitiveId,
  inputs: BuildInputs,
): BuildResult {
  const foundation = getFoundationModule(foundationId);
  const selected = pickBestCapability(foundation, target, foundationId);

  if (!selected) {
    return {
      target,
      steps: [
        makePlaceholderStep(
          foundation.name,
          target,
          inputs,
          `${foundation.name} has no reduction path to ${target} in this direction.`,
        ),
      ],
      oracle: null,
      foundationCapability: null,
      message: `${foundation.name} has no reduction path to ${target} in this direction.`,
    };
  }

  const foundationStep = executeFoundationCapability(foundation, selected.capability, inputs);
  if (!foundationStep) {
    return {
      target,
      steps: [
        makePlaceholderStep(
          foundation.name,
          target,
          inputs,
          `Capability ${selected.capability} is unavailable for ${foundation.name}.`,
        ),
      ],
      oracle: null,
      foundationCapability: null,
      message: `Capability ${selected.capability} is unavailable for ${foundation.name}.`,
    };
  }

  const steps: PrimitiveExecution[] = [foundationStep];
  let chainInput = foundationStep.outputHex;

  for (const reductionStep of selected.route) {
    const outputHex = transformByReduction(
      `${foundationId}|build|${reductionStep.from}|${reductionStep.to}`,
      chainInput,
      inputs.keyHex,
    );

    steps.push({
      primitive: reductionStep.to,
      functionApplied: reductionStep.functionApplied,
      inputHex: chainInput,
      outputHex,
      theorem: reductionStep.theorem,
      security: reductionStep.security,
      pa: reductionStep.pa,
      implemented: reductionStep.implemented,
      duePa: reductionStep.duePa,
      note: reductionStep.note,
    });

    chainInput = outputHex;
  }

  const oracle = composeOracle(foundation, selected.capability, selected.route, inputs.keyHex);

  return {
    target,
    steps,
    oracle,
    foundationCapability: selected.capability,
  };
}
