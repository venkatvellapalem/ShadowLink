const vm = require('vm');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

const sandbox = { URL, console };
vm.createContext(sandbox);

const ruleFiles = [
  'rules/constants.js',
  'rules/homoglyph.js',
  'rules/typosquatting.js',
  'rules/scoring.js',
  'rules/urlAnalyzer.js',
  'rules/domainReputation.js',
  'rules/urlShortener.js',
  'rules/urlEntropy.js',
  'core/threatEngine.js',
];

for (const file of ruleFiles) {
  vm.runInContext(fs.readFileSync(path.join(ROOT, file), 'utf-8'), sandbox, { filename: file });
}

function ctx(s) { return vm.runInContext(s, sandbox); }

const levenshtein = ctx('levenshtein');
const normalizeDomain = ctx('normalizeDomain');
const detectHomoglyph = ctx('detectHomoglyph');
const classifyThreat = ctx('classifyThreat');
const analyzeTyposquatting = ctx('analyzeTyposquatting');
const trustedDomains = ctx('trustedDomains');
const classifyTyposquatAttack = ctx('classifyTyposquatAttack');
const extractDomainLabel = ctx('extractDomainLabel');
const isBrandHostname = ctx('isBrandHostname');
const analyzeURL = ctx('analyzeURL');
const checkSuspiciousTLD = ctx('checkSuspiciousTLD');
const checkURLShortener = ctx('checkURLShortener');
const analyzeURLEntropy = ctx('analyzeURLEntropy');
const createThreatEngine = ctx('createThreatEngine');

let passed = 0, failed = 0;
function assert(ok, msg) {
  if (ok) { passed++; return; }
  failed++;
  console.error('  FAIL:', msg);
}

function group(name, fn) {
  console.log('\n' + name);
  fn();
}

// ── levenshtein ──────────────────────────────────────────────────────────────
group('levenshtein', () => {
  assert(levenshtein('', '') === 0, 'empty strings');
  assert(levenshtein('a', '') === 1, 'one empty');
  assert(levenshtein('', 'b') === 1, 'other empty');
  assert(levenshtein('paypal', 'paypal') === 0, 'identical');
  assert(levenshtein('paypal', 'paypa1') === 1, 'single substitution');
  assert(levenshtein('paypal', 'paypa') === 1, 'deletion');
  assert(levenshtein('paypal', 'xpaypal') === 1, 'insertion');
  assert(levenshtein('kitten', 'sitting') === 3, 'kitten→sitting');
});

// ── normalizeDomain ──────────────────────────────────────────────────────────
group('normalizeDomain', () => {
  assert(normalizeDomain('paypal') === 'paypal', 'already clean');
  assert(normalizeDomain('paypa1') === 'paypal', 'number 1→l');
  assert(normalizeDomain('g00gle') === 'google', 'double zero→oo');
  assert(normalizeDomain('micr0s0ft') === 'microsoft', 'mixed numbers');
  assert(normalizeDomain('rnicrosoft') === 'microsoft', 'rn→m');
  assert(normalizeDomain('pay-pal') === 'paypal', 'hyphen removed');
  assert(normalizeDomain('pay_pal') === 'paypal', 'underscore removed');
  assert(normalizeDomain('PAYPAL') === 'paypal', 'lowercased');
  assert(normalizeDomain('g00gle@pp') === 'googleapp', 'symbols');
});

// ── detectHomoglyph ──────────────────────────────────────────────────────────
group('detectHomoglyph', () => {
  const brands = ['paypal', 'google', 'microsoft', 'facebook'];
  assert(detectHomoglyph('paypal', brands).length === 0, 'exact match is safe');
  assert(detectHomoglyph('paypa1', brands).length === 0, 'paypa1 normalizes to paypal → safe');
  assert(detectHomoglyph('g00gle', brands).length === 0, 'g00gle normalizes to google → safe');
  assert(detectHomoglyph('paypals', brands).length >= 1, 'paypals → close to paypal');
  assert(detectHomoglyph('googles', brands).length >= 1, 'googles → close to google');
  assert(detectHomoglyph('googleapis', brands).length === 0, 'googleapis is legit extension');
  assert(detectHomoglyph('googleusercontent', brands).length === 0, 'googleusercontent is legit');
  assert(detectHomoglyph('gstatic', brands).length === 0, 'gstatic is legit');
  const hits = detectHomoglyph('paypals', brands);
  assert(hits.length >= 1 && hits[0] === 'paypal', 'returns matched brand name');
  assert(detectHomoglyph('evil', brands).length === 0, 'unrelated → empty');
});

// ── classifyThreat ───────────────────────────────────────────────────────────
group('classifyThreat', () => {
  assert(classifyThreat(0) === 'Safe', 'score 0 → Safe');
  assert(classifyThreat(24) === 'Safe', 'score 24 → Safe');
  assert(classifyThreat(25) === 'Suspicious', 'score 25 → Suspicious');
  assert(classifyThreat(49) === 'Suspicious', 'score 49 → Suspicious');
  assert(classifyThreat(50) === 'Critical', 'score 50 → Critical');
  assert(classifyThreat(74) === 'Critical', 'score 74 → Critical');
  assert(classifyThreat(75) === 'Dangerous', 'score 75 → Dangerous');
  assert(classifyThreat(100) === 'Dangerous', 'score 100 → Dangerous');
});

// ── helpers ──────────────────────────────────────────────────────────────────
group('helpers', () => {
  assert(extractDomainLabel('paypal.com') === 'paypal', 'extract simple');
  assert(extractDomainLabel('www.paypal.com') === 'paypal', 'strip www');
  assert(extractDomainLabel('login.paypal.com') === 'login', 'subdomain label');
  assert(isBrandHostname('paypal.com', 'paypal') === true, 'brand.com');
  assert(isBrandHostname('www.paypal.com', 'paypal') === true, 'www.brand.com');
  assert(isBrandHostname('paypal.org', 'paypal') === true, 'brand.org');
  assert(isBrandHostname('paypal.net', 'paypal') === true, 'brand.net');
  assert(isBrandHostname('evil.com', 'paypal') === false, 'unrelated');
  assert(isBrandHostname('paypal.com.evil.com', 'paypal') === false, 'subdomain of evil');
});

// ── classifyTyposquatAttack ──────────────────────────────────────────────────
group('classifyTyposquatAttack', () => {
  assert(classifyTyposquatAttack('paypal', 'paypal') === null, 'identical → null');
  assert(classifyTyposquatAttack('paypa1', 'paypal') === null, 'homoglyph norm equal → null');
  assert(classifyTyposquatAttack('g00gle', 'google') === null, 'homoglyph norm equal → null');
  assert(classifyTyposquatAttack('gooooogle', 'google') === 'repeated-letter', 'gooooogle');
  assert(classifyTyposquatAttack('paypall', 'paypal') === 'character-addition', 'paypall');
  assert(classifyTyposquatAttack('xpaypal', 'paypal') === 'character-addition', 'xpaypal');
  assert(classifyTyposquatAttack('paypbl', 'paypal') === 'character-substitution', 'paypbl');
});

// ── analyzeTyposquatting (end-to-end) ────────────────────────────────────────
group('analyzeTyposquatting', () => {
  let r;

  r = analyzeTyposquatting('https://paypall.com/login');
  assert(r.score > 0, 'paypall → score > 0');
  assert(r.matches.length === 1, 'paypall → 1 match');
  assert(r.matches[0].brand === 'paypal', 'paypall match brand = paypal');
  assert(r.indicators.length === 1, 'paypall → 1 indicator');

  r = analyzeTyposquatting('https://www.google.com');
  assert(r.score === 0, 'real google → score 0');
  assert(r.matches.length === 0, 'real google → 0 matches');

  r = analyzeTyposquatting('https://evil.com');
  assert(r.score === 0, 'unrelated → score 0');

  r = analyzeTyposquatting('https://micrsoft.com');
  assert(r.score > 0, 'micrsoft → score > 0');
  assert(r.matches.length === 1, 'micrsoft → 1 match');
  assert(r.matches[0].brand === 'microsoft', 'micrsoft match brand = microsoft');
});

// ── trustedDomains constants ─────────────────────────────────────────────────
group('trustedDomains', () => {
  assert(trustedDomains.includes('google'), 'has google');
  assert(trustedDomains.includes('paypal'), 'has paypal');
  assert(trustedDomains.includes('microsoft'), 'has microsoft');
  assert(trustedDomains.includes('facebook'), 'has facebook');
  assert(trustedDomains.length > 20, 'has plenty of brands');
});

// ── analyzeURL (urlAnalyzer.js) ──────────────────────────────────────────────
group('analyzeURL', () => {
  let r;

  r = analyzeURL('https://www.paypal.com');
  assert(r.indicators.length === 0, 'clean URL → no indicators');

  r = analyzeURL('https://evil.xyz/login');
  assert(r.indicators.length >= 1, 'suspicious TLD flagged');
  assert(r.indicators.some(i => i.includes('.xyz')), 'flags .xyz');

  r = analyzeURL('http://example.com');
  assert(r.indicators.some(i => i.includes('HTTPS')), 'HTTP flagged');

  r = analyzeURL('https://secure-login.example.com');
  assert(r.indicators.some(i => i.includes('secure')), 'suspicious keyword in hostname');

  r = analyzeURL('not-a-url');
  assert(r.indicators.length === 0, 'malformed URL → empty result');

  r = analyzeURL('https://paypa1s.com');
  assert(r.indicators.some(i => i.includes('homoglyph')), 'homoglyph near-miss flagged');
});

// ── checkSuspiciousTLD (domainReputation.js) ─────────────────────────────────
group('checkSuspiciousTLD', () => {
  assert(checkSuspiciousTLD('https://evil.xyz').length === 1, 'flags .xyz');
  assert(checkSuspiciousTLD('https://evil.top').length === 1, 'flags .top');
  assert(checkSuspiciousTLD('https://evil.tk').length === 1, 'flags .tk');
  assert(checkSuspiciousTLD('https://google.com').length === 0, 'clean .com');
  assert(checkSuspiciousTLD('https://example.com/page.xyz').length === 0, 'does not match path .xyz');
  assert(checkSuspiciousTLD('not-a-url').length === 0, 'malformed → empty');
});

// ── checkURLShortener (urlShortener.js) ──────────────────────────────────────
group('checkURLShortener', () => {
  let r;

  r = checkURLShortener('https://bit.ly/abc123');
  assert(r.isShortened === true, 'bit.ly → shortened');
  assert(r.score > 0, 'bit.ly → score > 0');
  assert(r.shortener === 'bit.ly', 'identifies bit.ly');

  r = checkURLShortener('https://tinyurl.com/abc');
  assert(r.isShortened === true, 'tinyurl → shortened');

  r = checkURLShortener('https://t.co/abc');
  assert(r.isShortened === true, 't.co → shortened');

  r = checkURLShortener('https://www.google.com');
  assert(r.isShortened === false, 'google → not shortened');
  assert(r.score === 0, 'google → score 0');
  assert(r.shortener === null, 'google → no shortener');

  r = checkURLShortener('not-a-url');
  assert(r.isShortened === false, 'malformed → not shortened');
});

// ── shannonEntropy (urlEntropy.js) ───────────────────────────────────────────
group('shannonEntropy', () => {
  const se = ctx('shannonEntropy');
  assert(se('') === 0, 'empty → 0');
  assert(se('aaaa') === 0, 'all same → 0');
  assert(se('a') === 0, 'single char → 0');
  assert(se('ab') > 0, 'two distinct → > 0');
  assert(se('abcdefgh') > se('aabbccdd'), 'more variety → higher entropy');
});

// ── analyzeURLEntropy (urlEntropy.js) ────────────────────────────────────────
group('analyzeURLEntropy', () => {
  let r;

  r = analyzeURLEntropy('https://google.com');
  assert(r.score === 0, 'google → 0 (safe label)');

  r = analyzeURLEntropy('https://paypal.com');
  assert(r.score === 0, 'paypal → 0 (safe label)');

  r = analyzeURLEntropy('https://www.ab.com');
  assert(r.score === 0, 'short label < 4 → skip');

  r = analyzeURLEntropy('https://xj29s8auth3k.xyz');
  assert(r.score > 0, 'high-entropy DGA → score > 0');
  assert(r.indicators.length >= 1, 'high-entropy → indicators');

  r = analyzeURLEntropy('https://a-b-c-d-e-f-g.xyz');
  assert(r.score > 0, 'many hyphens → score > 0');

  r = analyzeURLEntropy('not-a-url');
  assert(r.score === 0, 'malformed → 0');
});

// ── numericDensity / hyphenDensity / hasRandomConsonantCluster ───────────────
group('entropy helpers', () => {
  const nd = ctx('numericDensity');
  const hd = ctx('hyphenDensity');
  const rc = ctx('hasRandomConsonantCluster');

  assert(nd('') === 0, 'empty numeric density');
  assert(nd('abc') === 0, 'no digits → 0');
  assert(nd('a1b2c3') === 0.5, '3 of 6 chars → 0.5');
  assert(hd('a-b') > 0, 'hyphen density > 0');
  assert(hd('abc') === 0, 'no hyphens → 0');
  assert(rc('abcd') === false, '4 consonants → false');
  assert(rc('abcdfg') === true, '5+ consonants → true');
});

// ── createThreatEngine (threatEngine.js) ─────────────────────────────────────
group('createThreatEngine', () => {
  const eng = createThreatEngine();
  assert(eng.score === 0, 'starts at 0');
  assert(eng.indicators.length === 0, 'no indicators');
  assert(eng.breakdown.length === 0, 'no breakdown');

  eng.addThreat(25, 'test threat');
  assert(eng.score === 25, 'addThreat adds points');
  assert(eng.indicators.length === 1, 'addThreat adds indicator');
  assert(eng.indicators[0] === 'test threat', 'indicator text');
  assert(eng.breakdown.length === 1, 'addThreat adds breakdown');
  assert(eng.breakdown[0].points === 25, 'breakdown points');
  assert(eng.breakdown[0].reason === 'test threat', 'breakdown reason');

  eng.addThreat(50, 'second');
  assert(eng.score === 75, 'cumulative score');
  assert(eng.indicators.length === 2, 'cumulative indicators');
});

// ── Summary ──────────────────────────────────────────────────────────────────
console.log(`\n${passed + failed} tests, ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
