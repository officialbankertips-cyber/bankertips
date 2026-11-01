const fs = require("node:fs");
const vm = require("node:vm");
const assert = require("node:assert/strict");

const source = fs.readFileSync(require("node:path").join(__dirname, "..", "server.js"), "utf8");
function between(start, end) {
  const a = source.indexOf(start);
  const b = source.indexOf(end, a);
  assert.notEqual(a, -1, `missing source marker ${start}`);
  assert.notEqual(b, -1, `missing source marker ${end}`);
  return source.slice(a, b);
}
const context = vm.createContext({ FOOTBALL_TIME_ZONE: "Africa/Nairobi", Intl, Date, Number, String, Set, Math });
vm.runInContext([
  between("function normalizeTeamName", "function resolveTipMarket"),
  between("function resolveTipMarket", "function evaluateTipResult"),
  between("function evaluateTipResult", "async function fetchFootballFixturesForDate"),
  between("function findMatchingFixture", "async function syncTipResultsForDate")
].join("\n"), context);

const run = expression => vm.runInContext(expression, context);
const tests = [];
function test(name, fn) {
  try { fn(); tests.push({ name, ok: true }); }
  catch (error) { tests.push({ name, ok: false, error: error.message }); }
}

test("Turkish and accented team names normalize", () => {
  assert.equal(run('normalizeTeamName("Kasımpaşa")'), "kasimpasa");
  assert.equal(run('normalizeTeamName("Beşiktaş JK")'), "besiktas");
  assert.equal(run('normalizeTeamName("Fenerbahçe SK")'), "fenerbahce");
});
test("club suffixes and common aliases normalize", () => {
  assert.equal(run('normalizeTeamName("Manchester United FC")'), "manchester united");
  assert.equal(run('normalizeTeamName("Man Utd")'), "manchester united");
  assert.equal(run('normalizeTeamName("Inter Milan")'), "internazionale");
});
test("fixture matching preserves home-away orientation", () => {
  const fixture = { fixture:{id:123,date:"2026-11-01T16:00:00+03:00",timestamp:1793552400},
    teams:{home:{name:"Kasımpaşa"},away:{name:"Beşiktaş JK"}} };
  const good = run(`findMatchingFixture({homeTeam:"Kasimpasa",awayTeam:"Besiktas",date:"2026-11-01",time:"19:00"}, [${JSON.stringify(fixture)}])`);
  assert.equal(good.fixture.id, 123);
  const reversed = run(`findMatchingFixture({homeTeam:"Besiktas",awayTeam:"Kasimpasa",date:"2026-11-01",time:"19:00"}, [${JSON.stringify(fixture)}])`);
  assert.equal(reversed, null);
});
test("supported settlement markets calculate correct outcomes", () => {
  assert.equal(run('evaluateTipResult({tip:"Home Win",market:"auto"},2,0)'), "Win");
  assert.equal(run('evaluateTipResult({tip:"Draw",market:"auto"},1,1)'), "Win");
  assert.equal(run('evaluateTipResult({tip:"Away Win",market:"auto"},0,2)'), "Win");
  assert.equal(run('evaluateTipResult({tip:"1X",market:"auto"},1,1)'), "Win");
  assert.equal(run('evaluateTipResult({tip:"X2",market:"auto"},0,0)'), "Win");
  assert.equal(run('evaluateTipResult({tip:"12",market:"auto"},2,1)'), "Win");
  assert.equal(run('evaluateTipResult({tip:"BTTS Yes",market:"auto"},1,1)'), "Win");
  assert.equal(run('evaluateTipResult({tip:"BTTS No",market:"auto"},1,0)'), "Win");
  assert.equal(run('evaluateTipResult({tip:"Over 1.5",market:"auto"},1,1)'), "Win");
  assert.equal(run('evaluateTipResult({tip:"Under 2.5",market:"auto"},1,1)'), "Win");
  assert.equal(run('evaluateTipResult({tip:"Over 5.5",market:"auto"},3,3)'), "Win");
  assert.equal(run('evaluateTipResult({tip:"Under 0.5",market:"auto"},0,0)'), "Win");
  assert.equal(run('evaluateTipResult({tip:"Home DNB",market:"auto"},1,1)'), "Void");
  assert.equal(run('evaluateTipResult({tip:"Away DNB",market:"auto"},0,2)'), "Win");
  assert.equal(run('evaluateTipResult({tip:"Correct Score 2-1",market:"auto"},2,1)'), null);
});
test("provider match status labels use provider elapsed minute", () => {
  assert.equal(run('fixtureStatusLabel("2H",67)'), "67' · 2nd Half");
  assert.equal(run('fixtureStatusLabel("1H",23)'), "23' · 1st Half");
  assert.equal(run('fixtureStatusLabel("HT",45)'), "HT");
  assert.equal(run('fixtureStatusLabel("ET",105)'), "105' · Extra Time");
  assert.equal(run('fixtureStatusLabel("PEN",null)'), "PEN");
  assert.equal(run('fixtureStatusLabel("FT",null)'), "FT");
  assert.equal(run('fixtureStatusLabel("PST",null)'), "PST");
  assert.equal(run('fixtureStatusLabel("CANC",null)'), "CANC");
});

const failed = tests.filter(t => !t.ok);
for (const result of tests) {
  console.log(`${result.ok ? "PASS" : "FAIL"} ${result.name}${result.error ? `: ${result.error}` : ""}`);
}
console.log(`\n${tests.length - failed.length}/${tests.length} football logic tests passed.`);
if (failed.length) process.exitCode = 1;
