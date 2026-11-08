import type { DiagramDoc } from '../doc/types';
import type { RiskPolicy } from '../doc/risk';
import type { AccountUser, AuthFeatures, AuthResponse, ProjectDetail, ProjectSummary } from './types';

/**
 * Static-edition stand-in for the app's `account/api.ts`.
 *
 * A GitHub Pages deployment has no accounts service, so this module keeps the same
 * surface but answers `config` with "accounts disabled" instead of probing
 * `/api/config`. The account chip, project list and share dialogs therefore never
 * appear, no request is made, and the editor stays on browser storage.
 */

export const BROWSER_FEATURES: AuthFeatures = {
  authEnabled: false,
  registrationEnabled: false,
  guestLoginEnabled: false,
  guestTtlHours: 0,
  maxProjectBytes: 0,
  risk: null,
};

const OFFLINE =
  'Accounts and projects belong to the NMAP2Flowchart server build. This static edition keeps diagrams in your browser – export a design file to move one.';

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export type StoredSession = { token: string; expiresAt: number };

export function readStoredSession(): StoredSession | null {
  return null;
}

export function writeStoredSession(_session: StoredSession) {}

export function clearStoredSession() {}

export function readActiveProjectId(_userId: string): string | null {
  return null;
}

export function writeActiveProjectId(_userId: string, _projectId: string | null) {}

function offline<T>(): Promise<T> {
  return Promise.reject(new ApiError(OFFLINE, 0));
}

export const api = {
  config: () => Promise.resolve(BROWSER_FEATURES),

  login: (_username: string, _password: string) => offline<AuthResponse>(),

  register: (_username: string, _password: string, _email?: string) => offline<AuthResponse>(),

  guest: () => offline<AuthResponse>(),

  me: (_token: string) => offline<{ user: AccountUser }>(),

  logout: (_token: string) => offline<{ ok: boolean }>(),

  listProjects: (_token: string) => offline<{ projects: ProjectSummary[] }>(),

  getProject: (_token: string, _id: string) => offline<{ project: ProjectDetail }>(),

  createProject: (_token: string, _name: string, _doc: DiagramDoc) =>
    offline<{ project: ProjectSummary }>(),

  updateProject: (_token: string, _id: string, _patch: { name?: string; doc?: DiagramDoc }) =>
    offline<{ project: ProjectSummary }>(),

  deleteProject: (_token: string, _id: string) => offline<{ ok: boolean }>(),

  createShare: (_token: string, _id: string, _mode: 'edit' | 'view', _rotate = false) =>
    offline<{ project: ProjectSummary; url: string }>(),

  disableShare: (_token: string, _id: string) => offline<{ project: ProjectSummary }>(),

  getPreferences: (_token: string) => offline<{ risk: RiskPolicy | null }>(),

  savePreferences: (_token: string, _risk: RiskPolicy | null) => offline<{ risk: RiskPolicy | null }>(),
};
