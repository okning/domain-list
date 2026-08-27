import fs from "fs";
import path from "path";

const PUBLIC_PATH = path.resolve("public");
const MANIFEST_PATH = path.join(PUBLIC_PATH, "manifest.json");

function fail(message) {
  throw new Error(`Invalid static output: ${message}`);
}

function requireFile(filePath) {
  if (!fs.statSync(filePath, { throwIfNoEntry: false })?.isFile()) {
    fail(`missing ${path.relative(process.cwd(), filePath)}`);
  }
}

function rulePath(name, format) {
  return `/${format}/${name}.txt`;
}

requireFile(path.join(PUBLIC_PATH, "index.html"));
requireFile(MANIFEST_PATH);

const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));

if (manifest.schemaVersion !== 1) {
  fail(`unsupported manifest schema version ${manifest.schemaVersion}`);
}

if (Number.isNaN(Date.parse(manifest.generatedAt))) {
  fail("manifest generatedAt is not a valid date");
}

if (!Array.isArray(manifest.rules) || manifest.rules.length === 0) {
  fail("manifest contains no rules");
}

const names = new Set();

for (const rule of manifest.rules) {
  if (!/^[a-z0-9-]+$/.test(rule.name)) {
    fail(`invalid rule name ${JSON.stringify(rule.name)}`);
  }

  if (names.has(rule.name)) {
    fail(`duplicate rule name ${rule.name}`);
  }
  names.add(rule.name);

  for (const format of ["clash", "surge"]) {
    const expectedPath = rulePath(rule.name, format);
    if (rule[format] !== expectedPath) {
      fail(`${rule.name} has unexpected ${format} path ${JSON.stringify(rule[format])}`);
    }
    requireFile(path.join(PUBLIC_PATH, expectedPath));
  }
}

console.log(`Validated ${manifest.rules.length} rules in public/`);
