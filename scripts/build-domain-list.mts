import path from "path";
import fs from "fs";

const SOURCE_BASE_PATH = path.resolve("domain-list-community/data");
const TARGET_BASE_PATH = path.resolve("public");
const BASE_URL = "https://s.nosec.me";

const EntryType = {
  DOMAIN: "domain",
  FULL_DOMAIN: "full",
  KEYWORD: "keyword",
  REGEXP: "regexp",
  INCLUDE: "include",
} as const;

type EntryType = (typeof EntryType)[keyof typeof EntryType];

interface Entry {
  type: string;
  value: string;
  attrs: string[];
  affs: string[];
  plain: string;
}

class Processor {
  private parsed: Map<string, Entry[]> = new Map();
  private final: Map<string, Entry[]> = new Map();

  public dump() {
    const date = new Date().toUTCString();

    fs.mkdirSync(path.join(TARGET_BASE_PATH, "surge"), { recursive: true });
    fs.mkdirSync(path.join(TARGET_BASE_PATH, "clash"), { recursive: true });

    for (const [name, entries] of this.final) {
      const newName = name.replace("!", "non-");
      this.dumpSurge(newName, date, entries);
      this.dumpClash(newName, date, entries);
    }
  }

  public load(source: string) {
    fs.readdirSync(source).forEach((file) => {
      const filePath = path.join(source, file);
      if (!fs.statSync(filePath).isFile() || !/^[a-z0-9!-]+$/.test(file)) {
        return;
      }
      this.parse(filePath);
    });

    this.resolve_include();
  }

  private dumpSurge(name: string, date: string, entries: Entry[]) {
    const lines: string[] = this.header("surge", name, date, entries.length);

    for (const entry of entries) {
      switch (entry.type) {
        case EntryType.DOMAIN:
          lines.push(`DOMAIN-SUFFIX,${entry.value}`);
          break;
        case EntryType.FULL_DOMAIN:
          lines.push(`DOMAIN,${entry.value}`);
          break;
        case EntryType.KEYWORD:
          lines.push(`DOMAIN-KEYWORD,${entry.value}`);
          break;
        case EntryType.REGEXP:
          lines.push(`# REGEXP,${entry.value}`);
          break;
      }
    }

    fs.writeFileSync(path.join(TARGET_BASE_PATH, "surge", `${name}.txt`), lines.join("\n"));
  }

  private dumpClash(name: string, date: string, entries: Entry[]) {
    const lines: string[] = this.header("clash", name, date, entries.length);

    for (const entry of entries) {
      switch (entry.type) {
        case EntryType.DOMAIN:
          lines.push(`DOMAIN-SUFFIX,${entry.value}`);
          break;
        case EntryType.FULL_DOMAIN:
          lines.push(`DOMAIN,${entry.value}`);
          break;
        case EntryType.KEYWORD:
          lines.push(`DOMAIN-KEYWORD,${entry.value}`);
          break;
        case EntryType.REGEXP:
          lines.push(`DOMAIN-REGEXP,${entry.value}`);
          break;
      }
    }

    fs.writeFileSync(path.join(TARGET_BASE_PATH, "clash", `${name}.txt`), lines.join("\n"));
  }

  private header(app: string, name: string, date: string, total: number): string[] {
    const lines: string[] = [];
    lines.push(`# URL: ${new URL(`/${app}/${name}.txt`, BASE_URL).toString()}`);
    lines.push(`# Name: ${name}`);
    lines.push(`# Updated: ${date}`);
    lines.push(`# Total: ${total}`);
    lines.push("");
    return lines;
  }

  private resolve_include() {
    for (const [name, entries] of this.parsed) {
      const list: Entry[] = [];

      for (const entry of entries) {
        if (entry.type === EntryType.INCLUDE) {
          this.include(list, entry.value, entry.attrs);
        } else {
          list.push(entry);
        }
      }

      const domains: Set<string> = new Set();
      const final: Entry[] = [];
      const cache: Entry[] = [];

      for (const entry of list) {
        switch (entry.type) {
          case EntryType.DOMAIN:
          case EntryType.FULL_DOMAIN:
            domains.add(entry.value);
            cache.push(entry);
            break;
          default:
            final.push(entry);
        }
      }

      for (const entry of cache) {
        let domain = entry.value;
        let skip = false;

        while (true) {
          const index = domain.indexOf(".");
          if (index === -1) {
            break;
          }

          domain = domain.substring(index + 1);
          if (domains.has(domain)) {
            skip = true;
            break;
          }
        }

        if (!skip) {
          final.push(entry);
        }
      }

      this.final.set(
        name,
        final.sort((a, b) => a.plain.localeCompare(b.plain))
      );
    }
  }

  private include(list: Entry[], name: string, attrs: string[]) {
    const entries = this.parsed.get(name);
    const excludeAttrs: string[] = [];
    const mustAttrs: string[] = [];

    for (const attr of attrs) {
      if (attr.startsWith("-")) {
        excludeAttrs.push(attr.slice(1));
      } else {
        mustAttrs.push(attr);
      }
    }

    for (const entry of entries ?? []) {
      if (entry.type === EntryType.INCLUDE) {
        this.include(list, entry.value, entry.attrs.concat(attrs));
        continue;
      }

      if (attrs.length === 0) {
        list.push(entry);
        continue;
      }

      if (entry.attrs.some((attr) => excludeAttrs.includes(attr))) {
        continue;
      }

      if (mustAttrs.length > 0) {
        if (entry.attrs.some((attr) => mustAttrs.includes(attr))) {
          list.push(entry);
        }
      } else {
        list.push(entry);
      }
    }
  }

  private parse(filePath: string) {
    const content = fs.readFileSync(filePath, "utf-8");
    const lines = content.split(/\r?\n/).map((line) => line.trim());
    const list: Entry[] = [];

    for (const line of lines) {
      const content = line.split("#", 1)[0]?.trim();
      if (!content) {
        continue;
      }

      const entry = this.parseEntry(content);

      if (entry.type !== EntryType.INCLUDE) {
        for (const aff of entry.affs) {
          if (this.parsed.has(aff)) {
            this.parsed.get(aff)!.push(entry);
          } else {
            this.parsed.set(aff, [entry]);
          }
        }
      }

      list.push(entry);
    }

    const name = path.basename(filePath);
    if (this.parsed.has(name)) {
      this.parsed.get(name)!.push(...list);
    } else {
      this.parsed.set(name, list);
    }
  }

  private parseEntry(line: string): Entry {
    const entry: Entry = {
      type: EntryType.DOMAIN,
      value: "",
      attrs: [],
      affs: [],
      plain: "",
    };

    const parts = line.split(":", 2);
    if (parts.length === 2) {
      if (Object.values(EntryType).includes(parts[0] as EntryType)) {
        entry.type = parts[0] as EntryType;
      } else {
        throw new Error(`Invalid entry type: ${parts[0]}`);
      }

      entry.plain = parts[1]!.trim();
    } else {
      entry.plain = parts[0]!.trim();
    }

    const items = entry.plain.split(" ");

    for (const item of items.slice(1)) {
      if (item.startsWith("@")) {
        entry.attrs.push(item.slice(1));
      } else if (item.startsWith("&")) {
        entry.affs.push(item.slice(1));
      }
    }

    entry.value = items[0]!;
    return entry;
  }
}

const processer = new Processor();

processer.load(SOURCE_BASE_PATH);
processer.dump();
