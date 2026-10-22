import fs from 'node:fs';
import crypto from 'node:crypto';
import readline from 'node:readline';
import {createRequire} from 'node:module';
import {normalizeUserAgentForIdentity} from '/app/dist/services/userId/normalizeUserAgent.js';
import {bucketIpForIdentity} from '/app/dist/services/userId/identityIpBucket.js';
import {lookupAsn} from '/app/dist/db/geolocation/asn.js';
import {getLocation} from '/app/dist/db/geolocation/geolocation.js';
import {isDatacenterAsn} from '/app/dist/services/tracker/botBlocking/datacenterAsns.js';

const require = createRequire('/app/package.json');
const uaModule = require('ua-parser-js');
const UAParser = uaModule.UAParser ?? uaModule;
const key = fs.readFileSync(process.argv[2]);
const proxyIp = process.argv[3];
const sourceSiteId = Number(process.argv[4]);
if (!Number.isInteger(sourceSiteId) || sourceSiteId<=0) throw new Error('Invalid source site');
const Redis = require('ioredis');
const redis = new Redis({host:process.env.REDIS_HOST || 'localhost',
  port:Number(process.env.REDIS_PORT || 6379),
  ...(process.env.REDIS_PASSWORD ? {password:process.env.REDIS_PASSWORD} : {}),
  lazyConnect:true, commandTimeout:1000, maxRetriesPerRequest:1});
await redis.connect();
const digest = value => crypto.createHash('sha256').update(value).digest('hex').slice(0, 12);
const pseudonym = value => crypto.createHmac('sha256', key).update(value).digest('hex').slice(0, 24);
const uaCache = new Map();
const ipCache = new Map();
const aliasCache = new Map();
async function canonicalIdentity(nativeId) {
  if (aliasCache.has(nativeId)) return aliasCache.get(nativeId);
  let current = nativeId;
  const seen = new Set();
  for (let depth=0; depth<16; depth++) {
    if (seen.has(current)) throw new Error('Identity alias cycle');
    seen.add(current);
    const alias = await redis.get('sticky:alias:'+sourceSiteId+':'+current);
    if (!alias) {
      aliasCache.set(nativeId,current);
      return current;
    }
    if (!/^[a-f0-9]{12}$/.test(alias)) throw new Error('Unexpected identity alias');
    current = alias;
  }
  throw new Error('Identity alias chain exceeds limit');
}
const lines = readline.createInterface({input:process.stdin, crlfDelay:Infinity});
for await (const line of lines) {
  if (!line.trim()) continue;
  const record = JSON.parse(line);
  let agent = uaCache.get(record.ua);
  if (!agent) {
    const parsed = new UAParser(record.ua).getResult();
    agent = {
      normalized:normalizeUserAgentForIdentity(record.ua),
      browser:parsed.browser.name || '',
      browser_version:parsed.browser.major || '',
      operating_system:parsed.os.name || '',
      operating_system_version:parsed.os.version || '',
    };
    uaCache.set(record.ua, agent);
  }
  let address = ipCache.get(record.ip);
  if (!address) {
    const locations = await getLocation([record.ip]);
    const location = locations[record.ip];
    const asn = lookupAsn(record.ip);
    address = {
      identityIp:bucketIpForIdentity(record.ip),
      geo:{country:location?.countryIso || '\0\0', region:location?.region || '', city:location?.city || '',
           lat:location?.latitude || 0, lon:location?.longitude || 0, timezone:location?.timeZone || '',
           asn:asn?.asn ?? null, asn_org:asn?.organization || '', is_datacenter_asn:isDatacenterAsn(asn?.asn) ? 1 : 0},
    };
    ipCache.set(record.ip, address);
  }
  const nativeId = digest(address.identityIp + agent.normalized);
  const canonicalId = await canonicalIdentity(nativeId);
  const output = {
    log_id:record.log_id, start_ms:record.start_ms, end_ms:record.end_ms, hostname:record.hostname,
    old_id:digest(proxyIp + agent.normalized), native_id:nativeId, canonical_id:canonicalId,
    target_identity:pseudonym('native\0' + canonicalId),
    browser:agent.browser, browser_version:agent.browser_version,
    operating_system:agent.operating_system, operating_system_version:agent.operating_system_version,
    geo:address.geo,
  };
  process.stdout.write(JSON.stringify(output) + '\n');
}
await redis.quit();
