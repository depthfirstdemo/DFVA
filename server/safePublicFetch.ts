import axios from "axios";
import { lookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { BlockList, isIP } from "node:net";

export class UnsafeFetchUrlError extends Error {}

// Only globally routable destinations are eligible. Block special-use ranges
// even when the URL parser normalizes decimal, octal or short-form IPv4 literals.
const blockedIPv4 = new BlockList();
for (const [base, bits] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10],
  ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24],
  ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as Array<[string, number]>) {
  blockedIPv4.addSubnet(base, bits, "ipv4");
}

const globalIPv6 = new BlockList();
globalIPv6.addSubnet("2000::", 3, "ipv6");
const blockedIPv6 = new BlockList();
for (const [base, bits] of [
  ["2001::", 23], // protocol assignments, including Teredo
  ["2001:db8::", 32], ["2002::", 16], // documentation and 6to4 tunnels
  ["3fff::", 20], // documentation
] as Array<[string, number]>) {
  blockedIPv6.addSubnet(base, bits, "ipv6");
}

function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !blockedIPv4.check(address, "ipv4");
  if (family === 6) {
    // This also rejects ULA, link-local, IPv4-mapped and NAT64 addresses.
    return globalIPv6.check(address, "ipv6") && !blockedIPv6.check(address, "ipv6");
  }
  return false;
}

export async function safePublicHttpGet(input: string) {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new UnsafeFetchUrlError("Malformed URL.");
  }

  // Do not delegate redirects to axios: each hop must be resolved and checked.
  for (let redirects = 0; redirects <= 5; redirects++) {
    if ((url.protocol !== "http:" && url.protocol !== "https:") || !url.hostname || url.username || url.password) {
      throw new UnsafeFetchUrlError("Only HTTP(S) URLs without credentials are permitted.");
    }

    const hostname = url.hostname.replace(/^\[|\]$/g, "");
    const addresses = isIP(hostname)
      ? [{ address: hostname, family: isIP(hostname) }]
      : await lookup(hostname, { all: true });
    if (!addresses.length || addresses.some(({ address }) => !isPublicAddress(address))) {
      throw new UnsafeFetchUrlError("Requests to non-public addresses are not permitted.");
    }

    // Pin the checked address for the socket, retaining the original hostname
    // for Host, SNI and certificate verification. Ignore environment proxies,
    // which would otherwise bypass the validated lookup.
    const { address, family } = addresses[0];
    const agent = url.protocol === "https:"
      ? new https.Agent({ family, lookup: (_host, _options, callback) => callback(null, address, family as 4 | 6) })
      : new http.Agent({ family, lookup: (_host, _options, callback) => callback(null, address, family as 4 | 6) });
    try {
      const response = await axios.get(url.toString(), {
        timeout: 5000,
        proxy: false,
        maxRedirects: 0,
        ...(url.protocol === "https:" ? { httpsAgent: agent } : { httpAgent: agent }),
        validateStatus: status => status >= 200 && status < 400,
      });
      if (response.status < 300) return response;

      const location = response.headers.location;
      if (typeof location !== "string" || redirects === 5) {
        throw new UnsafeFetchUrlError("Redirect destination is not permitted.");
      }
      try {
        url = new URL(location, url);
      } catch {
        throw new UnsafeFetchUrlError("Malformed redirect URL.");
      }
    } finally {
      agent.destroy();
    }
  }
  throw new UnsafeFetchUrlError("Too many redirects.");
}
