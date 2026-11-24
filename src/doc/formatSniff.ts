/**
 * What a dropped file is, decided by content rather than extension.
 *
 * These checks run on every file and on every paste, so they live apart from the
 * readers: naming a design file or a draw.io drawing must not drag the XML parser
 * into the main bundle before anybody actually opens one.
 */

/** True when the text looks like a saved diagram rather than nmap XML. */
export function looksLikeJson(raw: string): boolean {
  return /^[\uFEFF\s]*[{[]/.test(raw);
}

export function looksLikeDrawio(text: string): boolean {
  const head = text.slice(0, 8192);
  return /<mxfile[\s>]/.test(head) || /<mxGraphModel[\s>]/.test(head);
}

export type ScanFormatHint = 'json' | 'drawio' | 'scan';

export function sniffFormat(raw: string): ScanFormatHint {
  if (looksLikeJson(raw)) return 'json';
  if (looksLikeDrawio(raw)) return 'drawio';
  return 'scan';
}
