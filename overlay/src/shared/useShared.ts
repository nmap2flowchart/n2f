import { useCallback } from 'react';

import type { DiagramDoc } from '../doc/types';
import type { SharedIncoming, SharedLive, SharedTarget, SharedUser } from './live';

export type SharedSession = {
  /** False until the page knows whether there is a room to join. */
  ready: boolean;
  enabled: boolean;
  live: SharedLive | null;
  users: SharedUser[];
  status: 'connecting' | 'live' | 'offline';
  incoming: SharedIncoming | null;
  kind: SharedTarget['kind'] | null;
  /** A view-only share link: the editor is locked and nothing is saved. */
  readOnly: boolean;
  /** True when this browser may write into the room (a share link with edit rights). */
  canPublish: boolean;
  /** The project name behind a share link, for the header. */
  title: string | null;
};

/**
 * Static-edition stand-in for the app's shared-room hook.
 *
 * GitHub Pages has no server to keep a room, so there is never anything to join:
 * the page is always the plain browser-storage editor. `App.tsx` keeps rendering it
 * the same way, it just never sees `enabled`, which also means no `/api/shared`
 * probe is made on load.
 */
export function useSharedSession(
  _target: SharedTarget | null,
): SharedSession & { publish: (doc: DiagramDoc) => void } {
  const publish = useCallback((_doc: DiagramDoc) => {}, []);

  return {
    ready: true,
    enabled: false,
    live: null,
    users: [],
    status: 'offline',
    incoming: null,
    kind: null,
    readOnly: false,
    canPublish: false,
    title: null,
    publish,
  };
}
