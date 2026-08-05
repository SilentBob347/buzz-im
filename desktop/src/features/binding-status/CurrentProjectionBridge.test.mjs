import assert from "node:assert/strict";
import test from "node:test";

import {
  createCurrentProjectionRevisionGate,
  mountCurrentProjectionBridge,
} from "./CurrentProjectionBridge.tsx";

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
}

async function flushPromises() {
  await Promise.resolve();
  await Promise.resolve();
}

function makeBridge() {
  const listenerReady = deferred();
  const snapshotReady = deferred();
  const applied = [];
  let eventHandler;
  let loadCalls = 0;
  let clearCalls = 0;
  let unlistenCalls = 0;

  const cleanup = mountCurrentProjectionBridge({
    listenForProjection(handler) {
      eventHandler = handler;
      return listenerReady.promise;
    },
    loadProjection() {
      loadCalls += 1;
      return snapshotReady.promise;
    },
    applyProjection(candidate) {
      applied.push(candidate);
    },
    clearProjection() {
      clearCalls += 1;
    },
  });

  return {
    applied,
    cleanup,
    emit: (candidate) => eventHandler(candidate),
    listenerReady,
    snapshotReady,
    get loadCalls() {
      return loadCalls;
    },
    get clearCalls() {
      return clearCalls;
    },
    get unlistenCalls() {
      return unlistenCalls;
    },
    registerListener() {
      listenerReady.resolve(() => {
        unlistenCalls += 1;
      });
    },
  };
}

test("registers the listener before requesting the native snapshot", async () => {
  const bridge = makeBridge();
  assert.equal(bridge.clearCalls, 1, "mount starts fail-closed");
  assert.equal(bridge.loadCalls, 0);

  bridge.registerListener();
  await flushPromises();
  assert.equal(bridge.loadCalls, 1);

  const snapshot = { connectionEpoch: "opaque-snapshot" };
  bridge.snapshotReady.resolve(snapshot);
  await flushPromises();
  assert.deepEqual(bridge.applied, [snapshot]);
  bridge.cleanup();
});

test("a live event fences a delayed bootstrap snapshot without ordering epochs", async () => {
  const bridge = makeBridge();
  bridge.registerListener();
  await flushPromises();

  const live = { connectionEpoch: "aaa" };
  bridge.emit(live);
  bridge.snapshotReady.resolve({ connectionEpoch: "zzz" });
  await flushPromises();

  assert.deepEqual(bridge.applied, [live]);
  bridge.cleanup();
});

test("snapshot failure clears only when no newer live event exists", async () => {
  const noEvent = makeBridge();
  noEvent.registerListener();
  await flushPromises();
  noEvent.snapshotReady.reject(new Error("getter unavailable"));
  await flushPromises();
  assert.equal(noEvent.clearCalls, 2);
  noEvent.cleanup();

  const newerEvent = makeBridge();
  newerEvent.registerListener();
  await flushPromises();
  const live = { connectionEpoch: "new-live-event" };
  newerEvent.emit(live);
  newerEvent.snapshotReady.reject(new Error("stale getter failure"));
  await flushPromises();
  assert.deepEqual(newerEvent.applied, [live]);
  assert.equal(newerEvent.clearCalls, 1);
  newerEvent.cleanup();
});

test("listener setup failure remains fail-closed and skips the getter", async () => {
  const bridge = makeBridge();
  bridge.listenerReady.reject(new Error("listen failed"));
  await flushPromises();

  assert.equal(bridge.loadCalls, 0);
  assert.equal(bridge.clearCalls, 2);
  assert.deepEqual(bridge.applied, []);
  bridge.cleanup();
});

test("teardown clears and rejects late listener and snapshot work", async () => {
  const beforeRegistration = makeBridge();
  beforeRegistration.cleanup();
  beforeRegistration.registerListener();
  await flushPromises();
  assert.equal(beforeRegistration.clearCalls, 2);
  assert.equal(beforeRegistration.unlistenCalls, 1);
  assert.equal(beforeRegistration.loadCalls, 0);

  const duringSnapshot = makeBridge();
  duringSnapshot.registerListener();
  await flushPromises();
  duringSnapshot.cleanup();
  duringSnapshot.snapshotReady.resolve({ connectionEpoch: "late" });
  await flushPromises();
  assert.equal(duringSnapshot.clearCalls, 2);
  assert.equal(duringSnapshot.unlistenCalls, 1);
  assert.deepEqual(duringSnapshot.applied, []);
});

test("the bridge accepts an injected revision gate", () => {
  let gateCreations = 0;
  const listenerReady = deferred();
  const cleanup = mountCurrentProjectionBridge({
    listenForProjection: () => listenerReady.promise,
    loadProjection: () => Promise.resolve(null),
    applyProjection: () => {},
    clearProjection: () => {},
    createGate(apply, clear) {
      gateCreations += 1;
      return createCurrentProjectionRevisionGate(apply, clear);
    },
  });

  assert.equal(gateCreations, 1);
  cleanup();
  listenerReady.resolve(() => {});
});
