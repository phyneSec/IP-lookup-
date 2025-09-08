import dns from "dns/promises";
import net from "net";
import geoip from "geoip-lite"; // untuk geolokasi offline

// Fungsi untuk port scanning sederhana
async function scanPorts(ip) {
  const portsToScan = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 8080];
  const results = [];

  for (let port of portsToScan) {
    const isOpen = await new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(1000);

      socket
        .connect(port, ip, () => {
          socket.destroy();
          resolve(true);
        })
        .on("error", () => resolve(false))
        .on("timeout", () => resolve(false));
    });

    results.push({ port, open: isOpen });
  }

  return results;
}

export default async function handler(req, res) {
  const { ip, domain } = req.query;

  try {
    let targetIP = ip;

    // Jika input domain
    if (domain) {
      const addresses = await dns.lookup(domain);
      targetIP = addresses.address;
    }

    if (!targetIP) {
      return res.status(400).json({ error: "Masukkan ?ip= atau ?domain=" });
    }

    // Geolokasi berdasarkan database offline
    const geo = geoip.lookup(targetIP) || {};

    // Port scan
    const ports = await scanPorts(targetIP);

    // DNS resolve jika domain
    let dnsRecords = {};
    if (domain) {
      dnsRecords = {
        A: await dns.resolve(domain, "A").catch(() => []),
        AAAA: await dns.resolve(domain, "AAAA").catch(() => []),
        MX: await dns.resolve(domain, "MX").catch(() => []),
        TXT: await dns.resolve(domain, "TXT").catch(() => []),
        NS: await dns.resolve(domain, "NS").catch(() => []),
      };
    }

    return res.status(200).json({
      target: domain || targetIP,
      ip: targetIP,
      geo,
      ports,
      dnsRecords,
      googleMaps: geo.ll
        ? `https://maps.google.com/?q=${geo.ll[0]},${geo.ll[1]}`
        : null,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
    }
