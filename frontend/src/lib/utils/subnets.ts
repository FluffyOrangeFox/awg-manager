import { isCIDR, isIPv4, isIPv6 } from './cidr';

/** IPv6 CIDR: литеральный адрес и маска 0–128. */
function isCIDR6(s: string): boolean {
  const slash = s.indexOf('/');
  if (slash === -1) return false;
  const prefix = s.substring(slash + 1);
  if (!/^\d{1,3}$/.test(prefix) || Number(prefix) > 128) return false;
  return isIPv6(s.substring(0, slash));
}

/**
 * Голый IPv4 → "/32", голый IPv6 → "/128" (совпасть с backend
 * splitBypassSubnets); CIDR как есть; иначе null. IPv6 приводится к нижнему
 * регистру, чтобы один и тот же адрес не попал в список дважды.
 */
export function normalizeSubnet(s: string): string | null {
  s = s.trim();
  if (isCIDR(s)) return s;
  if (isIPv4(s)) return s + '/32';
  if (isCIDR6(s)) return s.toLowerCase();
  if (isIPv6(s)) return s.toLowerCase() + '/128';
  return null;
}

/**
 * IPv6 ли это запись — по уже нормализованному значению. Такие исключения
 * действуют только при включённом перехвате IPv6 (бэкенд без него их
 * отвергает: checkV6SubnetsAccepted).
 */
export function isIPv6Subnet(normalized: string): boolean {
  return normalized.includes(':');
}

/** Split по запятой/пробелу, normalize, dedup; невалидные молча отброшены. */
export function parseSubnets(s: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const f of s.split(/[,\s]+/)) {
    const n = normalizeSubnet(f);
    if (n && !seen.has(n)) {
      seen.add(n);
      out.push(n);
    }
  }
  return out;
}

export function serializeSubnets(list: string[]): string {
  return list.join(', ');
}
