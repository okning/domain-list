#!/usr/bin/env python3

from dataclasses import dataclass, field
from urllib.parse import urljoin
from tabulate import tabulate
import pathlib
import time
import enum
import re

SOURCE_BASE_PATH = pathlib.Path("domain-list-community/data").absolute()
TARGET_BASE_PATH = pathlib.Path("dist").absolute()
BASE_URL = "https://domain-list.nosec.me"
UPDATED_TIME = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


class RuleType(enum.Enum):
    DOMAIN = "domain"
    FULL_DOMAIN = "full"
    KEYWORD = "keyword"
    REGEXP = "regexp"
    INCLUDE = "include"


@dataclass
class Inclusion:
    source: str = field(default="")
    must_attrs: list[str] = field(default_factory=list)
    ban_attrs: list[str] = field(default_factory=list)


@dataclass
class Entry:
    rule_type: RuleType = field(default=RuleType.DOMAIN)
    value: str = field(default="")
    attrs: list[str] = field(default_factory=list)
    plain: str = field(default="")


@dataclass
class ParsedList:
    name: str = field(default="")
    inclusions: list[Inclusion] = field(default_factory=list)
    entries: list[Entry] = field(default_factory=list)


def validate_domain_chars(domain: str) -> bool:
    return bool(domain) and all(
        c.islower() or c.isdigit() or c in {".", "-"} for c in domain
    )


def validate_attr_chars(attr: str) -> bool:
    return bool(attr) and all(c.islower() or c.isdigit() or c == "!" for c in attr)


def validate_site_name(name: str) -> bool:
    return bool(name) and all(
        c.islower() or c.isdigit() or c in {"!", "-"} for c in name
    )


def is_match_attr_filters(entry: Entry, inc_filter: Inclusion) -> bool:
    if len(entry.attrs) == 0:
        return len(inc_filter.must_attrs) == 0
    for m in inc_filter.must_attrs:
        if m not in entry.attrs:
            return False
    for b in inc_filter.ban_attrs:
        if b in entry.attrs:
            return False
    return True


class Processer:
    parsed_list_map: dict[str, ParsedList]
    final_map: dict[str, list[Entry]]
    circular_inclusion_map: set[str]

    def __init__(self) -> None:
        self.parsed_list_map = {}
        self.final_map = {}
        self.circular_inclusion_map = set()

    def get_or_create_parsed_list(self, name: str) -> ParsedList:
        if name not in self.parsed_list_map:
            self.parsed_list_map[name] = ParsedList(name)
        return self.parsed_list_map[name]

    def parse_line(self, line: str) -> tuple[RuleType, str]:
        parts = line.split(":", 1)
        if len(parts) != 2:
            rule_type, rule = RuleType.DOMAIN, parts[0]
        else:
            rule_type, rule = RuleType(parts[0].lower()), parts[1]
        return rule_type, rule

    def parse_attribute(self, attr: str) -> tuple[str, bool]:
        if attr[0] == "-":
            ban_attr = attr[1:]
            if not validate_attr_chars(ban_attr):
                raise ValueError(f"invalid attribute name: {ban_attr}")
            return ban_attr, True

        if not validate_attr_chars(attr):
            raise ValueError(f"invalid attribute name: {attr}")
        return attr, False

    def parse_inclusion(self, rule: str) -> Inclusion:
        parts = rule.split()
        if len(parts) == 0:
            raise ValueError("empty inclusion rule")

        inclusion = Inclusion(parts[0].lower())

        if not validate_site_name(inclusion.source):
            raise ValueError(f"invalid site name: {inclusion.source}")

        for part in parts[1:]:
            if part.startswith("@"):
                attr, is_ban = self.parse_attribute(part[1:].lower())
                if is_ban:
                    inclusion.ban_attrs.append(attr)
                else:
                    inclusion.must_attrs.append(attr)
            elif part.startswith("&"):
                raise ValueError(f"affiliation is not allowed for inclusion: {part}")
            else:
                raise ValueError(f"unknown field: {part}")

        return inclusion

    def plain(self, entry: Entry) -> str:
        attrs = ",".join(f"@{attr}" for attr in entry.attrs)
        if attrs != "":
            attrs = ":" + attrs
        return f"{entry.rule_type.value}:{entry.value}{attrs}"

    def parse_entry(self, rule_type: RuleType, rule: str) -> tuple[Entry, list[str]]:
        parts = rule.split()
        if len(parts) == 0:
            raise ValueError("empty entry rule")

        entry = Entry(rule_type)

        if rule_type in {RuleType.DOMAIN, RuleType.FULL_DOMAIN, RuleType.KEYWORD}:
            if not validate_domain_chars(parts[0]):
                raise ValueError(f"invalid domain: {parts[0]}")
            entry.value = parts[0]
        elif rule_type == RuleType.REGEXP:
            if re.compile(parts[0]) is None:
                raise ValueError(f"invalid regexp: {parts[0]}")
            entry.value = parts[0]
            return entry, []
        else:
            raise ValueError(f"unknown rule type: {rule_type}")

        affs: list[str] = []
        for part in parts[1:]:
            if part.startswith("@"):
                aff = part[1:].lower()
                if not validate_attr_chars(aff):
                    raise ValueError(f"invalid attribute name: {aff}")
                entry.attrs.append(aff)
            elif part.startswith("&"):
                aff = part[1:].lower()
                if not validate_site_name(aff):
                    raise ValueError(f"invalid affiliation name: {aff}")
                affs.append(aff)
            else:
                raise ValueError(f"unknown field: {part}")

        entry.plain = self.plain(entry)
        return (entry, affs)

    def load_data(self, name: str, file_path: pathlib.Path):
        parsed_list = self.get_or_create_parsed_list(name.lower())

        with file_path.open("r") as f:
            lines = f.readlines()

        line_num = 0
        for line in lines:
            line_num += 1
            line = line.split("#", 1)[0].strip()
            if line == "":
                continue

            try:
                rule_type, rule = self.parse_line(line)
            except ValueError as e:
                raise ValueError(f"{file_path}:{line_num}: {e}")

            if rule_type == RuleType.INCLUDE:
                parsed_list.inclusions.append(self.parse_inclusion(rule))
            else:
                entry, affs = self.parse_entry(rule_type, rule)
                for aff in affs:
                    self.get_or_create_parsed_list(aff.lower()).entries.append(entry)
                parsed_list.entries.append(entry)

    def polish_list(self, rough_list: dict[str, Entry]) -> list[Entry]:
        queuing_list: list[Entry] = []
        final_list: list[Entry] = []
        domains: set[str] = set()

        for entry in rough_list.values():
            if entry.rule_type in {RuleType.DOMAIN, RuleType.FULL_DOMAIN}:
                domains.add(entry.value)
                if len(entry.attrs) > 0:
                    final_list.append(entry)
                else:
                    queuing_list.append(entry)
            elif entry.rule_type in {RuleType.REGEXP, RuleType.KEYWORD}:
                final_list.append(entry)

        for entry in queuing_list:
            redundant = False
            pd = entry.value
            if entry.rule_type == RuleType.FULL_DOMAIN:
                pd = "." + pd
            while True:
                labels = pd.split(".", 1)
                if len(labels) == 1:
                    break
                pd = labels[1]
                if pd in domains:
                    redundant = True
                    break
            if not redundant:
                final_list.append(entry)

        final_list.sort(key=lambda e: e.plain)

        return final_list

    def resolve(self, name: str) -> None:
        if name not in self.parsed_list_map:
            raise ValueError(f"list not found: {name}")

        if name in self.final_map:
            return

        if name in self.circular_inclusion_map:
            raise ValueError(f"circular inclusion in: {name}")

        self.circular_inclusion_map.add(name)

        parsed_list = self.parsed_list_map[name]
        rough_list: dict[str, Entry] = {}

        for entry in parsed_list.entries:
            rough_list[entry.plain] = entry

        for inclusion in parsed_list.inclusions:
            self.resolve(inclusion.source)
            if inclusion.source not in self.final_map:
                continue

            done = len(inclusion.must_attrs) == 0 or len(inclusion.ban_attrs) == 0
            for entry in self.final_map[inclusion.source]:
                if done or is_match_attr_filters(entry, inclusion):
                    rough_list[entry.plain] = entry

        if len(rough_list) == 0:
            raise ValueError(f"empty list: {name}")

        self.final_map[name] = self.polish_list(rough_list)
        self.circular_inclusion_map.remove(name)


def write_surge(name: str, entries: list[Entry]) -> None:
    with pathlib.Path(TARGET_BASE_PATH / "surge" / name).open("w") as f:
        filtered = [e for e in entries if e.value]
        f.writelines(
            [
                f"# URL: {urljoin(BASE_URL, f'surge/{name}')}\n",
                f"# Name: {pathlib.Path(name).stem}\n",
                f"# Updated: {UPDATED_TIME}\n",
                f"# Total: {len(entries)}\n",
                "\n",
            ]
        )
        for entry in filtered:
            if entry.rule_type == RuleType.FULL_DOMAIN:
                f.write(f"DOMAIN,{entry.value}\n")
            elif entry.rule_type == RuleType.DOMAIN:
                f.write(f"DOMAIN-SUFFIX,{entry.value}\n")
            elif entry.rule_type == RuleType.KEYWORD:
                f.write(f"DOMAIN-KEYWORD,{entry.value}\n")
            elif entry.rule_type == RuleType.REGEXP:
                # surge does not support regexp, so we just write it as a comment
                f.write(f"# REGEXP,{entry.value}\n")
                pass


def write_clash(name: str, entries: list[Entry]) -> None:
    with pathlib.Path(TARGET_BASE_PATH / "clash" / name).open("w") as f:
        filtered = [e for e in entries if e.value]
        f.writelines(
            [
                f"# URL: {urljoin(BASE_URL, f'clash/{name}')}\n",
                f"# Name: {pathlib.Path(name).stem}\n",
                f"# Updated: {UPDATED_TIME}\n",
                f"# Total: {len(entries)}\n",
                "\n",
            ]
        )
        for entry in filtered:
            if entry.rule_type == RuleType.FULL_DOMAIN:
                f.write(f"DOMAIN,{entry.value}\n")
            elif entry.rule_type == RuleType.DOMAIN:
                f.write(f"DOMAIN-SUFFIX,{entry.value}\n")
            elif entry.rule_type == RuleType.KEYWORD:
                f.write(f"DOMAIN-KEYWORD,{entry.value}\n")
            elif entry.rule_type == RuleType.REGEXP:
                f.write(f"DOMAIN-REGEXP,{entry.value}\n")
                pass


def main() -> None:
    processer = Processer()

    for file in SOURCE_BASE_PATH.iterdir():
        if not file.is_file() or not validate_site_name(file.name):
            continue
        processer.load_data(file.name, file)

    for name in processer.parsed_list_map.keys():
        processer.resolve(name)

    pathlib.Path(TARGET_BASE_PATH / "surge").mkdir(parents=True, exist_ok=True)
    pathlib.Path(TARGET_BASE_PATH / "clash").mkdir(parents=True, exist_ok=True)

    names: list[str] = []

    for name, entries in processer.final_map.items():
        name = name.replace("!", "non-")
        names.append(name)
        name += ".txt"
        write_surge(name, entries)
        write_clash(name, entries)

    names.sort(key=lambda u: u)

    rows = [
        (
            name,
            urljoin(BASE_URL, f"surge/{name}.txt"),
            urljoin(BASE_URL, f"clash/{name}.txt"),
        )
        for name in names
    ]

    with pathlib.Path(TARGET_BASE_PATH / "quickstart.txt").open("w") as f:
        f.write(
            f"""Domain List Quickstart
======================

URL: {urljoin(BASE_URL, 'quickstart.txt')}
Updated: {UPDATED_TIME}
Total: {len(names)}

Usage
-----

Replace {{name}} with the actual name of the list, which can be found in the URL of each list.

{urljoin(BASE_URL, 'surge/{name}.txt')}

or

{urljoin(BASE_URL, 'clash/{name}.txt')}

Example
-------

For surge
^^^^^^^^^

.. code-block:: ini

  [General]
  skip-proxy = 127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,100.64.0.0/10,17.0.0.0/8,localhost
  exclude-simple-hostnames = true
  internet-test-url = http://www.apple.com/library/test/success.html
  proxy-test-url = http://www.gstatic.com/generate_204
  doh-server = https://doh.pub/dns-query
  dns-server = system, 223.5.5.5, 119.29.29.29
  hijack-dns = 8.8.8.8:53, 8.8.4.4:53
  ipv6 = true
  loglevel = notify
  allow-wifi-access = false
  
  [Proxy]
  
  [Proxy Group]
  Proxy = select, Auto, Manual, HK, SG, US, TW, KR, JP, include-all-proxies=0
  Auto = smart, include-other-group=Manual, hidden=1, include-all-proxies=0
  # NOTE: Change https://your-subscription-url.com to your actual subscription URL
  Manual = select, policy-path=https://your-subscription-url.com, update-interval=43200, include-all-proxies=0
  Media = select, Auto, Manual, HK, SG, US, TW, KR, JP, include-all-proxies=0
  AI = select, Auto, Manual, HK, SG, US, TW, KR, JP, include-all-proxies=0
  
  HK = smart, include-all-proxies=0, hidden=1, include-other-group=Manual, policy-regex-filter=香港
  SG = smart, include-all-proxies=0, hidden=1, include-other-group=Manual, policy-regex-filter=新加坡
  US = smart, include-all-proxies=0, hidden=1, include-other-group=Manual, policy-regex-filter=美国
  TW = smart, include-all-proxies=0, hidden=1, include-other-group=Manual, policy-regex-filter=台湾
  KR = smart, include-all-proxies=0, hidden=1, include-other-group=Manual, policy-regex-filter=韩国
  JP = smart, include-all-proxies=0, hidden=1, include-other-group=Manual, policy-regex-filter=日本
  
  [Rule]
  # Custom rules
  # External rules
  RULE-SET,https://domain-list.nosec.me/surge/google-gemini.txt,AI
  RULE-SET,https://domain-list.nosec.me/surge/openai.txt,AI
  RULE-SET,https://domain-list.nosec.me/surge/anthropic.txt,AI
  RULE-SET,https://domain-list.nosec.me/surge/youtube.txt,Media
  RULE-SET,https://domain-list.nosec.me/surge/spotify.txt,Media
  RULE-SET,https://domain-list.nosec.me/surge/disney.txt,Media
  RULE-SET,https://domain-list.nosec.me/surge/netflix.txt,Media
  RULE-SET,https://domain-list.nosec.me/surge/hulu.txt,Media
  RULE-SET,https://domain-list.nosec.me/surge/microsoft.txt,Proxy
  RULE-SET,https://domain-list.nosec.me/surge/telegram.txt,Proxy
  RULE-SET,https://domain-list.nosec.me/surge/cloudflare.txt,Proxy
  RULE-SET,https://domain-list.nosec.me/surge/homebrew.txt,Proxy
  RULE-SET,https://domain-list.nosec.me/surge/github.txt,Proxy
  RULE-SET,https://domain-list.nosec.me/surge/docker.txt,Proxy
  RULE-SET,https://domain-list.nosec.me/surge/google.txt,Proxy
  # Internal rules
  RULE-SET,SYSTEM,Proxy
  RULE-SET,LAN,DIRECT
  GEOIP,CN,DIRECT
  FINAL,Proxy,dns-failed

For clash
^^^^^^^^^

.. code-block:: yaml

  bind-address: 127.0.0.1
  mixed-port: 7890
  unified-delay: true
  allow-lan: false
  mode: rule
  ipv6: true
  log-level: info
  
  dns:
    enable: true
    ipv6: true
    enhanced-mode: fake-ip
    default-nameserver:
      - 8.8.8.8
      - 1.1.1.1
    nameserver:
      - 223.5.5.5
      - 119.29.29.29
      - https://doh.pub/dns-query
  
  proxy-providers:
    provider:
      type: http
      # NOTE: Change https://your-subscription-url.com to your actual subscription URL
      url: https://your-subscription-url.com
      interval: 43200
  
  proxies: []
  
  proxy-groups:
    - name: Proxy
      type: select
      proxies: [Auto, Manual, HK, SG, US, TW, KR, JP]
    - name: Auto
      type: url-test
      include-all-providers: true
      url: https://www.gstatic.com/generate_204
      hidden: true
    - name: Manual
      type: select
      include-all-providers: true
    - name: Media
      type: select
      proxies: [Auto, Manual, HK, SG, US, TW, KR, JP]
    - name: AI
      type: select
      proxies: [Auto, Manual, HK, SG, US, TW, KR, JP]
    - name: HK
      type: url-test
      include-all-providers: true
      filter: "香港"
      url: https://www.gstatic.com/generate_204
      hidden: true
    - name: SG
      type: url-test
      include-all-providers: true
      filter: "新加坡"
      url: https://www.gstatic.com/generate_204
      hidden: true
    - name: US
      type: url-test
      include-all-providers: true
      filter: "美国"
      url: https://www.gstatic.com/generate_204
      hidden: true
    - name: TW
      type: url-test
      include-all-providers: true
      filter: "台湾"
      url: https://www.gstatic.com/generate_204
      hidden: true
    - name: KR
      type: url-test
      include-all-providers: true
      filter: "韩国"
      url: https://www.gstatic.com/generate_204
      hidden: true
    - name: JP
      type: url-test
      include-all-providers: true
      filter: "日本"
      url: https://www.gstatic.com/generate_204
      hidden: true
  
  rule-providers:
    google-gemini:
      type: http
      url: https://domain-list.nosec.me/clash/google-gemini.txt
      interval: 43200
      behavior: classical
    openai:
      type: http
      url: https://domain-list.nosec.me/clash/openai.txt
      interval: 43200
      behavior: classical
    anthropic:
      type: http
      url: https://domain-list.nosec.me/clash/anthropic.txt
      interval: 43200
      behavior: classical
    youtube:
      type: http
      url: https://domain-list.nosec.me/clash/youtube.txt
      interval: 43200
      behavior: classical
    spotify:
      type: http
      url: https://domain-list.nosec.me/clash/spotify.txt
      interval: 43200
      behavior: classical
    disney:
      type: http
      url: https://domain-list.nosec.me/clash/disney.txt
      interval: 43200
      behavior: classical
    netflix:
      type: http
      url: https://domain-list.nosec.me/clash/netflix.txt
      interval: 43200
      behavior: classical
    hulu:
      type: http
      url: https://domain-list.nosec.me/clash/hulu.txt
      interval: 43200
      behavior: classical
    microsoft:
      type: http
      url: https://domain-list.nosec.me/clash/microsoft.txt
      interval: 43200
      behavior: classical
    telegram:
      type: http
      url: https://domain-list.nosec.me/clash/telegram.txt
      interval: 43200
      behavior: classical
    cloudflare:
      type: http
      url: https://domain-list.nosec.me/clash/cloudflare.txt
      interval: 43200
      behavior: classical
    github:
      type: http
      url: https://domain-list.nosec.me/clash/github.txt
      interval: 43200
      behavior: classical
    docker:
      type: http
      url: https://domain-list.nosec.me/clash/docker.txt
      interval: 43200
      behavior: classical
    google:
      type: http
      url: https://domain-list.nosec.me/clash/google.txt
      interval: 43200
      behavior: classical
  
  rules:
    # Custom rules
    # External rules
    - RULE-SET,google-gemini,AI
    - RULE-SET,openai,AI
    - RULE-SET,anthropic,AI
    - RULE-SET,youtube,Media
    - RULE-SET,spotify,Media
    - RULE-SET,disney,Media
    - RULE-SET,netflix,Media
    - RULE-SET,hulu,Media
    - RULE-SET,microsoft,Proxy
    - RULE-SET,telegram,Proxy
    - RULE-SET,cloudflare,Proxy
    - RULE-SET,github,Proxy
    - RULE-SET,docker,Proxy
    - RULE-SET,google,Proxy
    # Internal rules
    - GEOIP,CN,DIRECT
    - MATCH,Proxy

Domain List
-----------

{tabulate(rows, headers=['Name', 'Surge', 'Clash'], tablefmt='rst')}
"""
        )


if __name__ == "__main__":
    main()
