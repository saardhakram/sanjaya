import { parseLogs } from '../engine/parsers.js';
import { profilesFrom } from './features.js';
import { mulberry32 } from './iforest.js';
const pad = (n) => String(n).padStart(2, '0');
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
function webTime(ms) {
    const d = new Date(ms);
    return `${pad(d.getUTCDate())}/${MONTHS[d.getUTCMonth()]}/${d.getUTCFullYear()}:${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} +0000`;
}
function sysTime(ms) {
    const d = new Date(ms);
    return `${MONTHS[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, ' ')} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}
class Gen {
    r;
    constructor(r) {
        this.r = r;
    }
    float(a, b) {
        return a + this.r() * (b - a);
    }
    int(a, b) {
        return Math.floor(this.float(a, b + 1));
    }
    chance(p) {
        return this.r() < p;
    }
    pick(items) {
        return items[Math.floor(this.r() * items.length)];
    }
    /** Exponential inter-arrival time in ms with the given mean (seconds), at least 1 s. */
    gap(meanSeconds) {
        return Math.max(1000, Math.round(-Math.log(1 - this.r()) * meanSeconds * 1000));
    }
}
const BROWSERS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Version/18.1 Safari/605.1.15',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/131.0 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148',
    'Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0',
];
const SEARCHES = [
    'red shoes',
    "men's jacket",
    'size 10',
    'usb-c cable (2m)',
    'gift card',
    'café mug',
    'running shoes 50% off',
    'laptop bag',
];
const APP_AGENTS = [
    'okhttp/4.12.0',
    'ShopApp/3.4.1 (Android 14)',
    'ShopApp/3.4.0 (iPhone; iOS 18.1)',
    'python-requests/2.32.3',
    'Go-http-client/2.0',
    'axios/1.7.7',
];
const CRAWLERS = [
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
];
const MONITORS = ['UptimeRobot/2.0', 'kube-probe/1.31', 'Pingdom.com_bot_version_1.4'];
const ADMINS = ['alice', 'bob', 'deploy', 'ops', 'ci-runner', 'priya', 'arjun'];
const NOISE_PORTS = [23, 445, 3389, 5555, 8080, 2323, 1433, 5060, 6379, 9200];
function shopperPath(g) {
    return g.pick([
        () => '/',
        () => '/products',
        () => `/products.php?id=${g.int(1, 400)}`,
        () => `/category/${g.pick(['shoes', 'bags', 'jackets', 'home'])}?page=${g.int(1, 9)}&sort=${g.pick(['price', 'new', 'popular'])}`,
        () => `/search?q=${g.pick(SEARCHES)}`,
        () => '/cart',
        () => '/checkout',
        () => '/login',
        () => '/account/orders',
        () => `/blog/${g.pick(['how-to-choose-running-shoes', 'winter-care-guide', 'our-story'])}`,
        () => `/static/${g.pick(['css/main.3f9a.css', 'js/app.81bc.js', 'js/vendor.c02d.js'])}`,
        () => `/images/p/${g.int(1, 400)}.jpg`,
        () => '/favicon.ico',
        () => '/help/returns-policy',
    ])();
}
function webLine(ip, ms, method, path, status, ua) {
    return `${ip} - - [${webTime(ms)}] "${method} ${path} HTTP/1.1" ${status} ${status < 300 ? 4096 : 180} "-" "${ua}"`;
}
function shopperStatus(g, p404) {
    if (g.chance(p404))
        return 404;
    if (g.chance(0.003))
        return 500;
    if (g.chance(0.08))
        return 304;
    if (g.chance(0.03))
        return 302;
    return 200;
}
function shopper(g, ip, start, n = g.int(3, 80)) {
    const ua = g.pick(BROWSERS);
    const p404 = g.float(0, 0.05);
    let t = start;
    return Array.from({ length: n }, () => {
        t += g.gap(g.float(5, 30));
        const path = shopperPath(g);
        const method = /^\/(login|checkout)$/.test(path) && g.chance(0.5) ? 'POST' : 'GET';
        return webLine(ip, t, method, path, shopperStatus(g, p404), ua);
    });
}
function appClient(g, ip, start) {
    const ua = g.pick(APP_AGENTS);
    const mean = g.float(3, 15);
    let t = start;
    return Array.from({ length: g.int(20, 300) }, () => {
        t += g.gap(mean);
        const path = g.pick([
            () => `/api/v1/orders?since=${1763400000 + g.int(0, 99999)}`,
            () => `/api/v1/products/${g.int(1, 400)}`,
            () => '/api/v1/sync',
            () => '/api/v1/user/me',
            () => '/api/v1/events',
        ])();
        const status = g.chance(0.01) ? 401 : g.chance(0.005) ? 429 : g.chance(0.1) ? 304 : 200;
        return webLine(ip, t, path === '/api/v1/events' ? 'POST' : 'GET', path, status, ua);
    });
}
function crawler(g, ip, start) {
    const ua = g.pick(CRAWLERS);
    const p404 = g.float(0, 0.08);
    const mean = g.float(2, 10);
    let t = start;
    return Array.from({ length: g.int(10, 200) }, () => {
        t += g.gap(mean);
        const path = g.chance(0.6) ? `/products.php?id=${g.int(1, 5000)}` : shopperPath(g);
        const status = g.chance(p404) ? 404 : g.chance(0.05) ? 301 : 200;
        return webLine(ip, t, 'GET', path, status, ua);
    });
}
function monitor(g, ip, start) {
    const ua = g.pick(MONITORS);
    const every = g.pick([30, 60]) * 1000;
    const path = g.pick(['/health', '/', '/api/v1/health']);
    return Array.from({ length: g.int(10, 120) }, (_, i) => webLine(ip, start + i * every + g.int(0, 900), 'GET', path, g.chance(0.005) ? 503 : 200, ua));
}
function developer(g, ip, start) {
    let t = start;
    const p4xx = g.float(0.05, 0.35);
    return Array.from({ length: g.int(2, 15) }, () => {
        t += g.gap(20);
        const status = g.chance(p4xx) ? g.pick([400, 404, 401]) : 200;
        return webLine(ip, t, g.pick(['GET', 'POST']), `/api/v1/${g.pick(['orders', 'products/7', 'user/me', 'debug'])}`, status, 'curl/8.5.0');
    });
}
function sshAdmin(g, ip, start) {
    const users = [g.pick(ADMINS), ...(g.chance(0.2) ? [g.pick(ADMINS)] : [])];
    const lines = [];
    let t = start;
    for (let s = g.int(1, 6); s > 0; s--) {
        t += g.gap(600);
        const user = g.pick(users);
        const port = g.int(40000, 65000);
        if (g.chance(0.12)) {
            lines.push(`${sysTime(t)} web-01 sshd[${g.int(1000, 9999)}]: Failed password for ${user} from ${ip} port ${port} ssh2`);
            t += g.gap(8);
        }
        const method = g.chance(0.7) ? 'publickey' : 'password';
        lines.push(`${sysTime(t)} web-01 sshd[${g.int(1000, 9999)}]: Accepted ${method} for ${user} from ${ip} port ${port + 1} ssh2`);
        if (g.chance(0.5)) {
            lines.push(`${sysTime(t)} fw-01 kernel: [UFW ALLOW] IN=eth0 OUT= SRC=${ip} DST=10.0.0.5 PROTO=TCP SPT=${port} DPT=22`);
        }
    }
    return lines;
}
function backgroundNoise(g, ip, start) {
    const ports = [g.pick(NOISE_PORTS), ...(g.chance(0.3) ? [g.pick(NOISE_PORTS)] : [])];
    const lines = [];
    let t = start;
    for (let i = g.int(1, 4); i > 0; i--) {
        t += g.gap(300);
        const proto = g.chance(0.85) ? 'TCP' : 'UDP';
        lines.push(`${sysTime(t)} fw-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=${ip} DST=10.0.0.5 LEN=44 PROTO=${proto} SPT=${g.int(1024, 65000)} DPT=${g.pick(ports)}`);
    }
    if (g.chance(0.12)) {
        const user = g.pick(['admin', 'test', 'user', 'root']);
        lines.push(user === 'root'
            ? `${sysTime(t + 4000)} web-01 sshd[${g.int(1000, 9999)}]: Failed password for root from ${ip} port ${g.int(30000, 65000)} ssh2`
            : `${sysTime(t + 4000)} web-01 sshd[${g.int(1000, 9999)}]: Failed password for invalid user ${user} from ${ip} port ${g.int(30000, 65000)} ssh2`);
    }
    return lines;
}
function allowedClient(g, ip, start) {
    let t = start;
    return Array.from({ length: g.int(1, 5) }, () => {
        t += g.gap(120);
        return `${sysTime(t)} fw-01 kernel: [UFW ALLOW] IN=eth0 OUT= SRC=${ip} DST=10.0.0.5 PROTO=TCP SPT=${g.int(30000, 65000)} DPT=${g.pick([22, 80, 443])}`;
    });
}
function office(g, ip, start) {
    return [
        ...shopper(g, ip, start, g.int(20, 150)),
        ...sshAdmin(g, ip, start),
        ...allowedClient(g, ip, start),
    ];
}
const KINDS = [
    [36, shopper],
    [10, appClient],
    [8, crawler],
    [6, monitor],
    [5, developer],
    [10, sshAdmin],
    [15, backgroundNoise],
    [4, allowedClient],
    [6, office],
];
/** Generates `count` benign client profiles. Same seed ⇒ same profiles. */
export function benignProfiles(count, seed) {
    const g = new Gen(mulberry32(seed));
    const total = KINDS.reduce((s, [w]) => s + w, 0);
    const lines = [];
    const day = Date.UTC(2026, 10, 18);
    for (let i = 0; i < count; i++) {
        // Synthetic addresses in 100.64.0.0/10 (shared address space): never real public hosts.
        const ip = `100.${64 + Math.floor(i / 65536)}.${Math.floor(i / 256) % 256}.${i % 256}`;
        let roll = g.float(0, total);
        const kind = KINDS.find(([w]) => (roll -= w) < 0)?.[1] ?? shopper;
        lines.push(...kind(g, ip, day + g.int(0, 20 * 3600) * 1000));
    }
    const { events } = parseLogs(lines.join('\n'), { referenceYear: 2026 });
    return profilesFrom(events);
}
