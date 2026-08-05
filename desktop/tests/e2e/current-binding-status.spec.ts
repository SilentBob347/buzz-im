import { expect, test, type Page } from "@playwright/test";

import { installMockBridge, TEST_IDENTITIES } from "../helpers/bridge";

const MATCHING_MESSAGE = "Current binding belongs to this exact author.";
const OTHER_MESSAGE = "Current binding must not decorate this author.";
const LEGACY_ALIAS = "legacy-relay-alias-must-stay-hidden";
const CONNECTION_EPOCH = "11111111-1111-4111-8111-111111111111";

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
      page.evaluate(
        () => window.__BUZZ_E2E_EMIT_CURRENT_PROJECTION__?.(null) ?? false,
      ),
    )
    .toBe(true);
}

async function emitProjection(page: Page, payload: unknown) {
  const emitted = await page.evaluate((value) => {
    return window.__BUZZ_E2E_EMIT_CURRENT_PROJECTION__?.(value) ?? false;
  }, payload);
  if (!emitted) throw new Error("Native projection channel is not connected.");
}

test("current relay binding is exact-author, generic, clearable, and passively expiring", async ({
  page,
}) => {
  await installMockBridge(page);
  await page.goto("/");
  await page.getByTestId("channel-general").click();
  await expect(page.getByTestId("chat-title")).toHaveText("general");
  await waitForMockLiveSubscription(page);
  await waitForProjectionBridgeBootstrap(page);

  const createdAt = Math.floor(Date.now() / 1_000);
  await page.evaluate(
    ({ matchingMessage, otherMessage, matchingPubkey, otherPubkey, time }) => {
      const emit = window.__BUZZ_E2E_EMIT_MOCK_MESSAGE__;
      if (!emit) throw new Error("Mock live-message bridge is not installed.");

      emit({
        channelName: "general",
        content: otherMessage,
        createdAt: time,
        pubkey: otherPubkey,
      });
      emit({
        channelName: "general",
        content: matchingMessage,
        createdAt: time + 1,
        pubkey: matchingPubkey,
      });
    },
    {
      matchingMessage: MATCHING_MESSAGE,
      matchingPubkey: TEST_IDENTITIES.bob.pubkey,
      otherMessage: OTHER_MESSAGE,
      otherPubkey: TEST_IDENTITIES.charlie.pubkey,
      time: createdAt,
    },
  );

  const matchingRow = page
    .getByTestId("message-row")
    .filter({ hasText: MATCHING_MESSAGE });
  const otherRow = page
    .getByTestId("message-row")
    .filter({ hasText: OTHER_MESSAGE });
  await expect(matchingRow).toBeVisible();
  await expect(otherRow).toBeVisible();
  await expect(matchingRow.getByTestId("message-author")).toBeVisible();
  await expect(otherRow.getByTestId("message-author")).toBeVisible();

  const freshUntil = Math.floor(Date.now() / 1_000) + 30;
  await emitProjection(page, {
    connectionEpoch: CONNECTION_EPOCH,
    eventAuthorPubkey: TEST_IDENTITIES.bob.pubkey,
    freshUntil,
  });
  const badge = matchingRow.getByTestId("current-relay-binding");
  await expect(badge).toHaveCount(1);
  await expect(badge).toHaveAccessibleName("Current relay binding");
  await expect(otherRow.getByTestId("current-relay-binding")).toHaveCount(0);
  await expect(page.getByTestId("current-relay-binding")).toHaveCount(1);

  const badgeMarkup = (
    await badge.evaluate((element) => element.outerHTML)
  ).toLowerCase();
  for (const hiddenValue of [
    TEST_IDENTITIES.bob.pubkey,
    String(freshUntil),
    CONNECTION_EPOCH,
    LEGACY_ALIAS,
    "eventauthorpubkey",
    "freshuntil",
    "connectionepoch",
    "verifiedname",
  ]) {
    expect(badgeMarkup).not.toContain(hiddenValue.toLowerCase());
  }
  await expect(
    matchingRow.getByRole("img", { exact: true, name: LEGACY_ALIAS }),
  ).toHaveCount(0);

  for (const row of [matchingRow, otherRow]) {
    await expect(row.getByTestId("relay-verified-identity")).toHaveCount(0);
    await expect(
      row.locator('[aria-label^="Relay-verified identity"]'),
    ).toHaveCount(0);
    await expect(row).not.toContainText("Relay-verified identity");
    await expect(row).not.toContainText("Verified as");
    await expect(row).not.toContainText(LEGACY_ALIAS);
  }

  await emitProjection(page, null);
  await expect(page.getByTestId("current-relay-binding")).toHaveCount(0);

  const expiringFreshUntil = Math.floor(Date.now() / 1_000) + 4;
  await emitProjection(page, {
    connectionEpoch: "22222222-2222-4222-8222-222222222222",
    eventAuthorPubkey: TEST_IDENTITIES.bob.pubkey,
    freshUntil: expiringFreshUntil,
  });
  await expect(badge).toBeVisible();
  expect(await page.evaluate(() => Date.now() / 1_000)).toBeLessThan(
    expiringFreshUntil,
  );

  // No further event, navigation, or message update: the store's timer must
  // clear the projection when the exclusive freshUntil boundary is reached.
  await expect(page.getByTestId("current-relay-binding")).toHaveCount(0, {
    timeout: 7_000,
  });
  expect(await page.evaluate(() => Date.now() / 1_000)).toBeGreaterThanOrEqual(
    expiringFreshUntil,
  );
});
