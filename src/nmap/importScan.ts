import { runImport, type ImportRequest, type ImportResponse } from './runImport';

/**
 * Runs an import in a worker so the canvas keeps painting while a big scan is
 * parsed and laid out. Falls back to the same code inline when workers are not
 * available (an old browser, a test runner), which keeps one implementation.
 */

/** Above this the tab would visibly hitch on a slow machine, so say so first. */
export const LARGE_SCAN_BYTES = 4 * 1024 * 1024;

let counter = 0;

function inline(request: ImportRequest): Promise<ImportResponse> {
  return Promise.resolve().then(() => runImport(request));
}

function inWorker(request: ImportRequest): Promise<ImportResponse> {
  return new Promise((resolve, reject) => {
    let worker: Worker;
    try {
      worker = new Worker(new URL('./import.worker.ts', import.meta.url), {
        type: 'module',
        name: 'nmap-import',
      });
    } catch (error) {
      reject(error);
      return;
    }

    const id = (counter += 1);
    const finish = (response: ImportResponse) => {
      worker.terminate();
      resolve(response);
    };

    worker.onmessage = (event: MessageEvent<{ id: number; response: ImportResponse }>) => {
      if (event.data?.id !== id) return;
      finish(event.data.response);
    };
    worker.onerror = (event) => {
      worker.terminate();
      reject(new Error(event.message || 'The import worker stopped.'));
    };

    try {
      worker.postMessage({ id, request });
    } catch (error) {
      worker.terminate();
      reject(error);
    }
  });
}

export async function importScan(request: ImportRequest): Promise<ImportResponse> {
  if (typeof Worker === 'undefined') return inline(request);
  try {
    return await inWorker(request);
  } catch {
    // A blocked worker (CSP, an exotic browser) must not cost the user the import.
    return inline(request);
  }
}
