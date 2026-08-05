import { expect, test, type Locator, type Page } from "@playwright/test";

import { installMockBridge, TEST_IDENTITIES } from "../../helpers/bridge";
import {
  forwardTraceStep,
  loadCurrentBindingStatusTrace,
  traceStep,
  type NativeCurrentProjection,
} from "./currentBindingStatusTrace";

const trace = loadCurrentBindingStatusTrace();
const PROFILE_SPOOF_PREFIX = "profile-spoof-must-not-authorize";
const PROFILE_NIP05_PREFIX = "profile-nip05-must-not-authorize";

async function waitForMockLiveSubscription(page: Page) {
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          window.__BUZZ_E2E_HAS_MOCK_LIVE_SUBSCRIPTION__?.({
            channelName: "general",
          }) ?? false,
      ),
    )
    .toBe(true);
}

async function waitForProjectionBridgeBootstrap(page: Page) {
  await expect
    .poll(() =>
      page.evaluate(() =>
        window.__BUZZ_E2E_COMMANDS__?.includes(
          "get_current_binding_projection",
        ),
      ),
    )
    .toBe(true);

  await page.evaluate(
    () =>
      new Promise<void>((resolve) => {
        requestAnimationFrame(() => resolve());
      }),
  );
}

function otherSyntheticAuthor(projectedAuthors: ReadonlySet<string>): string {
  for (const identity of [TEST_IDENTITIES.bob, TEST_IDENTITIES.charlie]) {
    if (!projectedAuthors.has(identity.pubkey)) return identity.pubkey;
  }
  throw new Error(
    "Native trace unexpectedly contains both comparison authors.",
  );
}

async function emitMessage(
  page: Page,
  input: { content: string; pubkey: string; createdAt: number },
) {
  await page.evaluate((message) => {
    const emit = window.__BUZZ_E2E_EMIT_MOCK_MESSAGE__;
    if (!emit) throw new Error("Mock live-message bridge is not installed.");
    emit({ channelName: "general", ...message });
  }, input);
}

async function expectOnlyAuthorBadge(
  page: Page,
  rows: ReadonlyMap<string, Locator>,
  projection: NativeCurrentProjection,
) {
  const matchingRow = rows.get(projection.eventAuthorPubkey);
  if (!matchingRow) {
    throw new Error("No message row was created for the projected author.");
  }

  const badge = matchingRow.getByTestId("current-relay-binding");
  await expect(badge).toHaveCount(1);
  await expect(badge).toHaveAccessibleName("Current relay binding");
  await expect(page.getByTestId("current-relay-binding")).toHaveCount(1);

  for (const [author, row] of rows) {
    if (author !== projection.eventAuthorPubkey) {
      await expect(row.getByTestId("current-relay-binding")).toHaveCount(0);
    }
  }

  const badgeMarkup = (
    await badge.evaluate((element) => element.outerHTML)
  ).toLowerCase();
  for (const hiddenValue of [
    projection.eventAuthorPubkey,
    String(projection.freshUntil),
    projection.connectionEpoch,
    PROFILE_SPOOF_PREFIX,
    PROFILE_NIP05_PREFIX,
    "eventauthorpubkey",
    "freshuntil",
    "connectionepoch",
  ]) {
    expect(badgeMarkup).not.toContain(hiddenValue.toLowerCase());
  }
}

async function expectNoLegacyTrustPresentation(page: Page) {
  await expect(page.getByTestId("relay-verified-identity")).toHaveCount(0);
  await expect(
    page.locator('[aria-label^="Relay-verified identity"]'),
  ).toHaveCount(0);
  await expect(page.getByText("Binding active", { exact: false })).toHaveCount(
    0,
  );
  await expect(page.getByText("Verified as", { exact: false })).toHaveCount(0);
}

test("Rust native-flow projections drive exact-author lifecycle presentation", async ({
  page,
}) => {
  const currentProjections = trace.steps.flatMap((step) =>
    step.projection === null ? [] : [step.projection],
  );
  const projectedAuthors = new Set(
    currentProjections.map((projection) => projection.eventAuthorPubkey),
  );
  const expiryProjection = currentProjections.reduce((earliest, projection) =>
    projection.freshUntil < earliest.freshUntil ? projection : earliest,
  );
  const clockStartSeconds = expiryProjection.freshUntil - 2;
  if (clockStartSeconds <= 0) {
    throw new Error(
      "Native trace freshUntil is too small for expiry coverage.",
    );
  }

  await page.clock.install({ time: clockStartSeconds * 1_000 });
  await installMockBridge(page, {
    searchProfiles: [...projectedAuthors].map((pubkey, index) => ({
      pubkey,
      displayName: `${PROFILE_SPOOF_PREFIX}-${index}`,
      nip05Handle: `${PROFILE_NIP05_PREFIX}-${index}@example.invalid`,
    })),
  });
  await page.goto("/");
  await page.getByTestId("channel-general").click();
  await expect(page.getByTestId("chat-title")).toHaveText("general");
  await waitForMockLiveSubscription(page);
  await waitForProjectionBridgeBootstrap(page);

  const rows = new Map<string, Locator>();
  let createdAt = clockStartSeconds - projectedAuthors.size - 1;
  for (const [index, pubkey] of [...projectedAuthors].entries()) {
    const content = `Native projection author ${index}`;
    await emitMessage(page, { content, pubkey, createdAt: createdAt++ });
    const row = page.getByTestId("message-row").filter({ hasText: content });
    await expect(row).toBeVisible();
    await expect(row.getByTestId("message-author")).toContainText(
      `${PROFILE_SPOOF_PREFIX}-${index}`,
    );
    rows.set(pubkey, row);
  }

  const otherAuthor = otherSyntheticAuthor(projectedAuthors);
  const otherContent = "Non-projected comparison author";
  await emitMessage(page, {
    content: otherContent,
    pubkey: otherAuthor,
    createdAt,
  });
  const otherRow = page
    .getByTestId("message-row")
    .filter({ hasText: otherContent });
  await expect(otherRow).toBeVisible();
  rows.set(otherAuthor, otherRow);

  for (const step of trace.steps) {
    await forwardTraceStep(page, step);
    if (step.projection === null) {
      await expect(page.getByTestId("current-relay-binding")).toHaveCount(0);
    } else {
      await expectOnlyAuthorBadge(page, rows, step.projection);
    }
  }

  // These native lifecycle outputs must all clear presentation. Naming them
  // explicitly keeps this browser layer non-vacuous if the trace grows later.
  for (const caseName of [
    "withdrawal",
    "passive-expiry",
    "disconnect",
    "logout",
    "restart",
    "relay-scope-change",
    "signer-scope-change",
    "author-scope-change",
    "domain-scope-change",
    "epoch-scope-change",
    "profile-spoof",
    "nip85-no-fallback",
  ] as const) {
    expect(traceStep(trace, caseName).projection).toBeNull();
  }
  expect(traceStep(trace, "reconnect").projection).not.toBeNull();
  await expectNoLegacyTrustPresentation(page);

  // Re-deliver an unchanged DTO produced by Rust while the browser clock is
  // before its deadline, then advance to the exclusive boundary. No later
  // trace event, render fixture, or navigation clears it.
  const expiryStep = trace.steps.find(
    (step) => step.projection === expiryProjection,
  );
  if (!expiryStep) throw new Error("Expiry projection is absent from trace.");
  await forwardTraceStep(page, expiryStep);
  await expectOnlyAuthorBadge(page, rows, expiryProjection);
  await page.clock.fastForward(
    (expiryProjection.freshUntil - clockStartSeconds) * 1_000,
  );
  await expect(page.getByTestId("current-relay-binding")).toHaveCount(0);
  await expectNoLegacyTrustPresentation(page);
});
