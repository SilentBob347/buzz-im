import { readFileSync } from "node:fs";
import { isAbsolute } from "node:path";

import type { Page } from "@playwright/test";

import { CURRENT_PROJECTION_EVENT } from "../../../src/features/binding-status/CurrentProjectionBridge";
import type { CurrentProjection } from "../../../src/features/binding-status/currentProjectionStore";

const TRACE_ENV = "BUZZ_J3C_PROJECTION_TRACE";
const LOWERCASE_HEX_256 = /^[0-9a-f]{64}$/;

export const CURRENT_BINDING_TRACE_CASES = [
  "bootstrap",
  "current",
  "duplicate",
  "equal-conflict",
  "rollback",
  "newer-restoration",
  "withdrawal",
  "passive-expiry",
  "disconnect",
  "reconnect",
  "logout",
  "restart",
  "relay-scope-change",
  "signer-scope-change",
  "author-scope-change",
  "domain-scope-change",
  "epoch-scope-change",
  "malformed-trusted",
  "unsupported-version",
  "author-mismatch",
  "profile-spoof",
  "nip85-no-fallback",
] as const;

const CASES_WITH_CURRENT_PROJECTION = new Set<CurrentBindingTraceCase>([
  "current",
  "duplicate",
  "newer-restoration",
  "reconnect",
]);

export type CurrentBindingTraceCase =
  (typeof CURRENT_BINDING_TRACE_CASES)[number];

export type NativeCurrentProjection = CurrentProjection;

export type CurrentBindingTraceStep = Readonly<{
  case: CurrentBindingTraceCase;
  projection: NativeCurrentProjection | null;
}>;

export type CurrentBindingStatusTrace = Readonly<{
  version: 1;
  steps: readonly CurrentBindingTraceStep[];
}>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: string[]) {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return (
    actual.length === sortedExpected.length &&
    actual.every((key, index) => key === sortedExpected[index])
  );
}

function isCurrentProjection(value: unknown): value is NativeCurrentProjection {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["connectionEpoch", "eventAuthorPubkey", "freshUntil"])
  ) {
    return false;
  }

  return (
    typeof value.eventAuthorPubkey === "string" &&
    LOWERCASE_HEX_256.test(value.eventAuthorPubkey) &&
    typeof value.freshUntil === "number" &&
    Number.isSafeInteger(value.freshUntil) &&
    value.freshUntil > 0 &&
    typeof value.connectionEpoch === "string" &&
    LOWERCASE_HEX_256.test(value.connectionEpoch)
  );
}

function parseTrace(value: unknown, path: string): CurrentBindingStatusTrace {
  if (!isRecord(value) || !hasExactKeys(value, ["steps", "version"])) {
    throw new Error(`${path} is not an exact J3C projection trace object.`);
  }
  if (value.version !== 1 || !Array.isArray(value.steps)) {
    throw new Error(`${path} must contain trace version 1 and a steps array.`);
  }
  if (value.steps.length !== CURRENT_BINDING_TRACE_CASES.length) {
    throw new Error(
      `${path} must contain exactly ${CURRENT_BINDING_TRACE_CASES.length} trace steps.`,
    );
  }

  for (const [index, expectedCase] of CURRENT_BINDING_TRACE_CASES.entries()) {
    const step = value.steps[index];
    if (!isRecord(step) || !hasExactKeys(step, ["case", "projection"])) {
      throw new Error(`${path} step ${index} is not an exact trace step.`);
    }
    if (step.case !== expectedCase) {
      throw new Error(
        `${path} step ${index} must be case ${expectedCase}, received ${String(step.case)}.`,
      );
    }

    const expectsCurrent = CASES_WITH_CURRENT_PROJECTION.has(expectedCase);
    if (
      (expectsCurrent && !isCurrentProjection(step.projection)) ||
      (!expectsCurrent && step.projection !== null)
    ) {
      throw new Error(
        `${path} case ${expectedCase} has an invalid retained projection.`,
      );
    }
  }

  // Return the parsed objects themselves. The Playwright boundary forwards the
  // native DTO without rebuilding, enriching, or substituting it.
  return value as CurrentBindingStatusTrace;
}

export function loadCurrentBindingStatusTrace(): CurrentBindingStatusTrace {
  const path = process.env[TRACE_ENV];
  if (!path) {
    throw new Error(
      `${TRACE_ENV} is required and must name the Rust native-flow trace.`,
    );
  }
  if (!isAbsolute(path)) {
    throw new Error(`${TRACE_ENV} must be an absolute path; received ${path}.`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    const reason = error instanceof Error ? error.message : "unknown error";
    throw new Error(`Unable to read ${TRACE_ENV} at ${path}: ${reason}.`);
  }
  return parseTrace(parsed, path);
}

export function traceStep(
  trace: CurrentBindingStatusTrace,
  caseName: CurrentBindingTraceCase,
): CurrentBindingTraceStep {
  const step = trace.steps.find((candidate) => candidate.case === caseName);
  if (!step) {
    throw new Error(`Native projection trace is missing case ${caseName}.`);
  }
  return step;
}

export async function forwardTraceStep(
  page: Page,
  step: CurrentBindingTraceStep,
): Promise<void> {
  await page.evaluate(
    async ({ eventName, projection }) => {
      const emit = window.__BUZZ_E2E_EMIT_TAURI_EVENT__;
      if (!emit) throw new Error("Mock Tauri event bridge is not installed.");
      await emit(eventName, projection);
    },
    {
      eventName: CURRENT_PROJECTION_EVENT,
      projection: step.projection,
    },
  );
}
