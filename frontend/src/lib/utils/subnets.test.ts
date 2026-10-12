import { describe, it, expect } from 'vitest';
import { isIPv6Subnet, normalizeSubnet, parseSubnets, serializeSubnets } from './subnets';

describe('normalizeSubnet', () => {
  it('keeps valid CIDR', () => expect(normalizeSubnet('203.0.113.0/24')).toBe('203.0.113.0/24'));
  it('promotes bare IP to /32', () => expect(normalizeSubnet('10.8.0.5')).toBe('10.8.0.5/32'));
  it('rejects hostname', () => expect(normalizeSubnet('vpn.example.com')).toBeNull());
  it('rejects garbage', () => expect(normalizeSubnet('nope')).toBeNull());
  // IPv6 — для перехвата IPv6 в режиме TPROXY; бэкенд делит список по семействам.
  it('keeps valid IPv6 CIDR, lowercased', () => expect(normalizeSubnet('2001:DB8::/32')).toBe('2001:db8::/32'));
  it('promotes bare IPv6 to /128', () => expect(normalizeSubnet('2001:db8::1')).toBe('2001:db8::1/128'));
  it('rejects IPv6 prefix over 128', () => expect(normalizeSubnet('2001:db8::/129')).toBeNull());
  it('rejects IPv4 prefix over 32', () => expect(normalizeSubnet('10.0.0.0/33')).toBeNull());
  it('rejects ip:port lookalike', () => expect(normalizeSubnet('8.8.8.8:53')).toBeNull());
});

describe('parseSubnets', () => {
  it('splits comma+space and dedups', () =>
    expect(parseSubnets('203.0.113.0/24, 10.8.0.5 10.8.0.5')).toEqual(['203.0.113.0/24', '10.8.0.5/32']));
  it('drops invalid silently', () =>
    expect(parseSubnets('10.0.0.0/8, bad')).toEqual(['10.0.0.0/8']));
  it('empty → []', () => expect(parseSubnets('')).toEqual([]));
  it('keeps both families and dedups IPv6 by case', () =>
    expect(parseSubnets('10.8.0.5, 2001:db8::/32 2001:DB8::/32')).toEqual(['10.8.0.5/32', '2001:db8::/32']));
});

describe('isIPv6Subnet', () => {
  it('IPv6 CIDR', () => expect(isIPv6Subnet('2001:db8::/32')).toBe(true));
  it('bare IPv6 promoted to /128', () => expect(isIPv6Subnet('2001:db8::1/128')).toBe(true));
  it('IPv4 CIDR', () => expect(isIPv6Subnet('10.0.0.0/8')).toBe(false));
});

describe('serializeSubnets', () => {
  it('joins with comma-space', () =>
    expect(serializeSubnets(['10.0.0.0/8', '1.2.3.4/32'])).toBe('10.0.0.0/8, 1.2.3.4/32'));
});
