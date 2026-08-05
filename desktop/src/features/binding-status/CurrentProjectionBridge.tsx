import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { useEffect } from "react";

import {
  applyCurrentProjectionFromNative,
  clearCurrentProjection,
} from "./currentProjectionStore";

export const CURRENT_PROJECTION_EVENT = "current-binding-projection-changed";
export const CURRENT_PROJECTION_GETTER = "get_current_binding_projection";

type SnapshotFence = {
  resolve: (candidate: unknown) => void;
  reject: () => void;
};

export type CurrentProjectionRevisionGate = {
  applyEvent: (candidate: unknown) => void;
  beginSnapshot: () => SnapshotFence;
  failClosed: () => void;
  close: () => void;
};

type CurrentProjectionBridgeDependencies = {
  listenForProjection: (
    handler: (candidate: unknown) => void,
  ) => Promise<UnlistenFn>;
  loadProjection: () => Promise<unknown>;
  applyProjection: (candidate: unknown) => void;
  clearProjection: () => void;
  createGate?: (
    applyProjection: (candidate: unknown) => void,
    clearProjection: () => void,
  ) => CurrentProjectionRevisionGate;
};

/**
 * Fence browser-local async work without interpreting the opaque native epoch.
 */
export function createCurrentProjectionRevisionGate(
  applyProjection: (candidate: unknown) => void,
  clearProjection: () => void,
): CurrentProjectionRevisionGate {
  let revision = 0;
  let active = true;

  return {
    applyEvent(candidate) {
      if (!active) return;
      revision += 1;
      applyProjection(candidate);
    },
    beginSnapshot() {
      const capturedRevision = revision;
      let settled = false;
      const claimFence = () => {
        if (settled) return false;
        settled = true;
        return active && revision === capturedRevision;
      };
      return {
        resolve(candidate) {
          if (claimFence()) applyProjection(candidate);
        },
        reject() {
          if (claimFence()) clearProjection();
        },
      };
    },
    failClosed() {
      if (!active) return;
      revision += 1;
      clearProjection();
    },
    close() {
      if (!active) return;
      active = false;
      revision += 1;
      clearProjection();
    },
  };
}

const defaultDependencies: CurrentProjectionBridgeDependencies = {
  listenForProjection: (handler) =>
    listen<unknown>(CURRENT_PROJECTION_EVENT, (event) => {
      handler(event.payload);
    }),
  loadProjection: () => invoke<unknown>(CURRENT_PROJECTION_GETTER),
  applyProjection: applyCurrentProjectionFromNative,
  clearProjection: clearCurrentProjection,
};

/**
 * Register the live listener before reading the native snapshot. The local
 * revision fence prevents a delayed bootstrap result from replacing a newer
 * event; opaque connection epochs are deliberately never compared in React.
 */
export function mountCurrentProjectionBridge(
  dependencies: CurrentProjectionBridgeDependencies = defaultDependencies,
): () => void {
  let active = true;
  let unlisten: UnlistenFn | null = null;
  const gate = (dependencies.createGate ?? createCurrentProjectionRevisionGate)(
    dependencies.applyProjection,
    dependencies.clearProjection,
  );

  // Mounting must not expose state left by an earlier bridge lifecycle.
  dependencies.clearProjection();

  void dependencies
    .listenForProjection((candidate) => gate.applyEvent(candidate))
    .then(async (registeredUnlisten) => {
      if (!active) {
        registeredUnlisten();
        return;
      }

      unlisten = registeredUnlisten;
      const snapshotFence = gate.beginSnapshot();
      try {
        const candidate = await dependencies.loadProjection();
        snapshotFence.resolve(candidate);
      } catch {
        snapshotFence.reject();
      }
    })
    .catch(() => {
      if (active) gate.failClosed();
    });

  return () => {
    if (!active) return;
    active = false;
    gate.close();
    unlisten?.();
    unlisten = null;
  };
}

export function CurrentProjectionBridge(): null {
  useEffect(() => mountCurrentProjectionBridge(), []);
  return null;
}
