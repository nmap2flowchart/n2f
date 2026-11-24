/**
 * Which of the shapes nmap can write a file in.
 *
 * Decided by content, never by extension: `-oX` output saved as `.txt` is still
 * XML, and a `-oG` file is still grepable when somebody calls it `scan.xml`.
 */
import type { NmapHost, VulnRef } from '../model/types';
import { vulnsOf } from '../model/vulns';

export type ScanFormat = 'xml' | 'grepable' | 'normal' | 'unknown';

/**
 * Stamp every host and port with the scan it came from, so a merge can say what
 * changed and when, and attach the vulnerabilities the scripts reported.
 * Shared by all three readers.
 */
export function stampHosts(hosts: NmapHost[], fileName: string, startedAt: string | undefined): NmapHost[] {
  return hosts.map((host) => {
    const stamped: NmapHost = {
      ...host,
      ...(startedAt ? { seenAt: startedAt } : {}),
      scanFile: fileName,
      ports: host.ports.map((port) => ({
        ...port,
        ...(startedAt ? { firstSeen: startedAt, lastSeen: startedAt } : {}),
      })),
    };
    const vulns: VulnRef[] = vulnsOf(stamped);
    return vulns.length > 0 ? { ...stamped, vulns } : stamped;
  });
}

export function detectScanFormat(text: string): ScanFormat {
  const head = text.slice(0, 8192);
  if (/<nmaprun[\s>]/.test(head) || /^\s*<\?xml/.test(head)) return 'xml';
  // -oG: the header comment, then one tab-separated line per host.
  if (/^# Nmap .*scan initiated/im.test(head) || /^Host: \S+/m.test(head)) return 'grepable';
  // -oN: the report block, then the port table.
  if (/^Nmap scan report for /m.test(head) || /^Starting Nmap /m.test(head)) return 'normal';
  return 'unknown';
}
