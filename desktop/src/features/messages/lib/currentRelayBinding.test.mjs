import assert from "node:assert/strict";
import test from "node:test";

import { hasCurrentRelayBindingForAuthor } from "./currentRelayBinding.ts";

const projection = {
  eventAuthorPubkey: "abcdef",
};

test("returns false without a current projection", () => {
  assert.equal(hasCurrentRelayBindingForAuthor(null, "abcdef"), false);
});

test("returns true for the exact event author", () => {
  assert.equal(hasCurrentRelayBindingForAuthor(projection, "abcdef"), true);
});

test("does not normalize author case", () => {
  assert.equal(hasCurrentRelayBindingForAuthor(projection, "ABCDEF"), false);
});

test("does not trim author whitespace", () => {
  assert.equal(hasCurrentRelayBindingForAuthor(projection, " abcdef"), false);
  assert.equal(hasCurrentRelayBindingForAuthor(projection, "abcdef "), false);
});

test("returns false for a different or absent event author", () => {
  assert.equal(hasCurrentRelayBindingForAuthor(projection, "fedcba"), false);
  assert.equal(hasCurrentRelayBindingForAuthor(projection, null), false);
  assert.equal(hasCurrentRelayBindingForAuthor(projection, undefined), false);
});
