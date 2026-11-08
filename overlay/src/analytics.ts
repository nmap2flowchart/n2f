/**
 * Google Analytics 4 for the static edition.
 *
 * The measurement ID comes from `public/config.js` (`window.N2F_GA_ID`). While it
 * is empty – the shipped default – no script is injected and no request leaves the
 * browser, so the page works the same before and after a code is filled in.
 */

declare global {
  interface Window {
    N2F_GA_ID?: string;
    dataLayer?: unknown[][];
    gtag?: (...args: unknown[]) => void;
  }
}

const MEASUREMENT_ID = /^G-[A-Z0-9]{4,}$/i;
const PLACEHOLDER = /^G-X{4,}$/i;

export function initAnalytics(): void {
  const id = (window.N2F_GA_ID ?? '').trim();
  if (!MEASUREMENT_ID.test(id) || PLACEHOLDER.test(id)) return;

  const loader = document.createElement('script');
  loader.async = true;
  loader.src = `https://www.googletagmanager.com/gtag/js?id=${encodeURIComponent(id)}`;
  document.head.append(loader);

  // gtag queues its calls on `dataLayer` until the loader above has downloaded.
  const queue: unknown[][] = [];
  window.dataLayer = queue;
  const gtag = (...args: unknown[]) => {
    queue.push(args);
  };
  window.gtag = gtag;

  gtag('js', new Date());
  gtag('config', id, { anonymize_ip: true });
}
