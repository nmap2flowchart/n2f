import { DEVICE_KIND_ICONS, classifyHost, virtualPlatformOf } from '../model/device';
import type { NmapHost, NmapOsMatch } from '../model/types';

/**
 * Which icon a card wears, from the evidence a scan carries.
 *
 * This is deliberately separate from `registry.tsx`: the import worker needs an
 * icon id and nothing else, and the registry's icon set builds React elements and
 * embeds every OS logo, which has no business in a worker bundle.
 */

/**
 * What the scan calls the device, by model or vendor string. Consumer and prosumer
 * routers answer "OpenWrt" or "Linux" to OS fingerprinting, so the model name is a
 * better signal for what the box *is* than the firmware it happens to run.
 */
const APPLIANCE_PATTERNS: [RegExp, string][] = [
  // ASUS: RT-AX55, RT-AC68U, ZenWiFi, plus the ASUSWRT firmware name.
  [/rt-ax\d|rt-ac\d|rt-n\d|gt-ax\d|zenwifi|asuswrt|\basus\b/i, 'wrouter'],
  // Ubiquiti/UniFi and EdgeMAX model names. The bare "ubiquiti" vendor string is
  // left to the vendor table, which maps it to a plain router.
  [/unifi|\budm\b|\busg\b|\buxg\b|edgerouter|edgemax|airmax/i, 'wrouter'],
  // TP-Link, Deco, Omada; Netgear Nighthawk/Orbi; Linksys Velop; AVM Fritz!Box.
  [/\barcher\b|\bdeco\b|\btl-(wr|er)\d|omada|tp-?link/i, 'wrouter'],
  [/nighthawk|\borbi\b|\b(r|rax|mr|mx)\d{3,4}\b|netgear/i, 'wrouter'],
  [/velop|\beero\b|linksys/i, 'wrouter'],
  [/fritz|\bavm\b/i, 'wrouter'],
  // Model families only. A bare "MikroTik RouterOS" in an OS *guess* is not a
  // device: nmap reports it for plenty of Linux VMs, so the vendor table handles it.
  [/routerboard|\bhap\b|\brb\d{3,4}\b|\bccr\d+\b/i, 'wrouter'],
];

const OS_PATTERNS: [RegExp, string][] = [
  [/linux mint|\bmint\b/i, 'mint'],
  [/ubuntu/i, 'ubuntu'],
  [/raspbian|raspberry pi/i, 'raspberrypi'],
  [/debian/i, 'debian'],
  [/kali/i, 'kali'],
  [/alma\s*linux|almalinux/i, 'alma'],
  [/rocky\s*linux|rockylinux/i, 'rocky'],
  [/centos/i, 'centos'],
  [/red hat|rhel/i, 'rhel'],
  [/fedora/i, 'fedora'],
  [/arch linux|\barch\b/i, 'arch'],
  [/alpine/i, 'alpine'],
  [/gentoo/i, 'gentoo'],
  [/nixos/i, 'nixos'],
  [/opensuse|suse/i, 'suse'],
  [/openwrt|lede\b|dd-wrt/i, 'openwrt'],
  [/opnsense/i, 'opnsense'],
  [/pfsense/i, 'pfsense'],
  [/proxmox|\bpve\b/i, 'proxmox'],
  [/xcp-?ng|citrix hypervisor/i, 'hypervisor'],
  [/diskstation|synology|\bdsm\b/i, 'synology'],
  [/truenas|freenas/i, 'truenas'],
  [/esxi|vmkernel|vmware/i, 'vmware'],
  [/android/i, 'android'],
  [/thinclient|terminal/i, 'desktop'],
  // Cisco IOS is a network OS, not Apple's iOS – check it before the mac/iOS rule.
  [/cisco ios|ios xe|ios xr|junos/i, 'router'],
  [/mac ?os|macos|darwin|\bapple\b|\bios\b/i, 'macos'],
  [/openbsd/i, 'openbsd'],
  [/freebsd/i, 'freebsd'],
  [/microsoft windows|windows/i, 'windows'],
  [/linux|unix/i, 'linux'],
];

/** OS ids that describe a *family* (a kernel) rather than a role. */
const GENERIC_OS_IDS = new Set(['linux', 'windows', 'freebsd', 'openbsd', 'macos', 'android']);

// Hypervisors and their management UIs come before the container rule: a Proxmox
// host usually runs docker too, and "this machine runs VMs" is the better label.
const SERVICE_PATTERNS: [RegExp, string][] = [
  [/proxmox|pveproxy|pve-manager|xcp-?ng|vmware|esxi|hyper-v|virtio/i, 'hypervisor'],
  [/gitlab|gitea|forgejo|gogs|bitbucket/i, 'git'],
  [/plex|jellyfin|emby|kodi|serviio|subsonic/i, 'media'],
  [/prometheus|grafana|zabbix|netdata|influxdb|librenms|checkmk/i, 'monitoring'],
  [/opnsense|pfsense|sophos|fortigate|palo alto/i, 'firewall'],
  [/docker|podman|containerd/i, 'docker'],
  [/kubernetes|k8s/i, 'kubernetes'],
  [/synology|qnap|freenas|truenas|diskstation/i, 'nas'],
  [/hikvision|dahua|axis|ipcam|rtsp|onvif/i, 'camera'],
  [/brother|hewlett|canon|epson|xerox|jetdirect|ipp/i, 'printer'],
  [/mysql|postgres|mssql|mongodb|mariadb|oracle|redis|elasticsearch/i, 'database'],
  [/openvpn|wireguard|ipsec|strongswan/i, 'vpn'],
  [/postfix|exim|dovecot|smtp|imap/i, 'mail'],
  // Word boundaries matter here: "rpcbind" on port 111 used to satisfy a bare
  // `bind`, which is how firewall and hypervisor boxes ended up with a DNS icon.
  [/\bbind\b|dnsmasq|\bnamed\b|unbound|\bdomain\b/i, 'dns'],
  [/nginx|openresty|apache|lighttpd|httpd|jenkins|tomcat/i, 'web'],
  [/routeros|cisco|juniper|mikrotik|ubiquiti|unifi|openwrt/i, 'router'],
  [/aws|azure|gcp|cloudflare|s3/i, 'cloud'],
];

const VENDOR_ICONS: [RegExp, string][] = [
  // Virtual NIC vendors (Proxmox, VMware) are deliberately absent: they mean "this
  // is a guest", not "this is the hypervisor", so they must not claim an icon.
  [/synology|qnap|seagate|western digital|drobo/i, 'nas'],
  [/hikvision|dahua|axis|reolink|amcrest|ezviz/i, 'camera'],
  [/brother|canon|epson|xerox|lexmark|ricoh/i, 'printer'],
  [/ubiquiti|cisco|juniper|mikrotik|tp-link|netgear|d-link|aruba|fortinet|palo alto/i, 'router'],
];

/**
 * nmap lists several OS guesses at the same accuracy, and its distro guesses are
 * unreliable: a Proxmox VM ties "Linux 4.15 - 5.19" with "OpenWrt 21.02" and
 * "MikroTik RouterOS" at 100 each. A distro may only pick an icon when no generic
 * family is tied with it – otherwise the role has to come from what the box serves.
 */
function plausibleMatches(host: NmapHost): NmapOsMatch[] {
  if (host.os.length === 0) return [];
  const best = host.os.reduce((max, match) => Math.max(max, match.accuracy), 0);
  return host.os.filter((match) => match.accuracy >= best - 3);
}

function unambiguousOs(host: NmapHost): string[] {
  const plausible = plausibleMatches(host);
  const genericBest = plausible
    .filter((match) => guessId(match.name) !== undefined)
    .reduce((max, match) => Math.max(max, match.accuracy), -1);
  return plausible
    .filter((match) => guessId(match.name) === undefined)
    .filter((match) => match.accuracy > genericBest)
    .map((match) => match.name);
}

/** The kernel family a guess names, but only when it *starts* with it: "OpenWrt 21.02
 *  (Linux 5.4)" is an OpenWrt guess, not a Linux one. */
function guessId(name: string): string | undefined {
  if (/^(microsoft\s+)?windows/i.test(name)) return 'windows';
  if (/^(mac ?os|macos|darwin|ios)\b/i.test(name)) return 'macos';
  if (/^(freebsd|openbsd|netbsd)\b/i.test(name)) return 'bsd';
  if (/^android\b/i.test(name)) return 'android';
  if (/^(linux|unix)\b/i.test(name)) return 'linux';
  return undefined;
}

/** Windows/macOS when every plausible guess agrees – those two say more about the
 *  machine than any single service banner does. */
function soleDesktopOs(host: NmapHost): string | undefined {
  const families = new Set(plausibleMatches(host).map((match) => guessId(match.name)));
  if (families.size !== 1) return undefined;
  const [family] = [...families];
  return family === 'windows' || family === 'macos' ? family : undefined;
}

export function detectIcon(host: NmapHost | undefined): string {
  if (!host) return 'unknown';

  // 0. A NIC that only exists inside a hypervisor: the card is a guest, and that
  //    is what the icon should say before any appliance or OS rule gets a say.
  if (virtualPlatformOf(host)) return 'vm';

  // 1. What the device is, by model or vendor string: an ASUS RT-AX55 running
  //    OpenWrt is still a wireless router on the map.
  const identity = [host.hostnames.join(' '), host.vendor ?? '', host.os.map((match) => match.name).join(' ')].join(
    ' ',
  );
  for (const [pattern, id] of APPLIANCE_PATTERNS) {
    if (pattern.test(identity)) return id;
  }

  // 1b. nmap's own classification, which the rules below cannot see: the
  //     `<osclass type>` category, `-sV`'s devicetype/ostype, CPE identifiers and
  //     NSE output (smb-os-discovery, snmp-sysdescr, http-title). Only a
  //     categorical signature is allowed to decide here – a port guess is not.
  const profile = classifyHost(host);
  if (profile.signatureKind) {
    const mapped = DEVICE_KIND_ICONS[profile.kind];
    if (mapped) return mapped;
  }

  // 2. A fingerprinted platform naming a role – but only when the guess is not tied
  //    with a bare "Linux", which nmap offers for almost every x86 box.
  const roles = unambiguousOs(host);
  for (const [pattern, id] of OS_PATTERNS) {
    if (GENERIC_OS_IDS.has(id) || id === 'android') continue;
    if (roles.some((name) => pattern.test(name))) return id;
  }

  // 3. Windows/macOS, when the scan is sure. This beats a web banner: a Windows
  //    workstation that happens to answer on 80 is still a Windows workstation.
  const desktop = soleDesktopOs(host);
  if (desktop) return desktop;

  // 4. The NIC vendor: real hardware vendors (Ubiquiti, Synology, Brother…) say more
  //    than the software a box happens to run. Virtual NIC vendors are excluded.
  for (const [pattern, id] of VENDOR_ICONS) {
    if (host.vendor && pattern.test(host.vendor)) return id;
  }

  // 5. What the open ports actually serve.
  const serviceText = host.ports
    .map((port) => [port.service, port.product, port.extrainfo].filter(Boolean).join(' '))
    .join(' ');
  for (const [pattern, id] of SERVICE_PATTERNS) {
    if (pattern.test(serviceText)) return id;
  }

  // 6. Port shape, when the banners said nothing.
  const open = new Set(host.ports.filter((port) => port.state === 'open').map((port) => port.port));
  if (open.has(8006) || open.has(902) || open.has(903)) return 'hypervisor';
  if (open.has(3389)) return 'windows';
  if (open.has(9100) || open.has(515) || open.has(631)) return 'printer';
  if (open.has(554)) return 'camera';
  if (open.has(53) && open.size <= 2) return 'dns';

  // 7. "It runs Linux" is the least informative answer, so it comes last.
  for (const [pattern, id] of OS_PATTERNS) {
    if (!GENERIC_OS_IDS.has(id)) continue;
    if (host.os.some((match) => pattern.test(match.name))) return id;
  }
  if (open.has(22) || open.has(80) || open.has(443) || open.has(445)) return 'server';

  return 'desktop';
}

