"""
Tests for main.py – covering validators, parsers, resolve logic, and writers.

The test suite also verifies that the inclusion-filter bug fix (or → and in
resolve()) produces correct behaviour:
  OLD:  done = len(must)==0 OR  len(ban)==0   ← bypasses filtering when only one side is set
  NEW:  done = len(must)==0 AND len(ban)==0   ← only skips filtering when both are empty
"""

import pathlib
import textwrap
import pytest

# ── Import helpers from main.py ────────────────────────────────────────────────
import sys
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from main import (
    RuleType,
    SURGE_RULE_TYPE_MAP,
    CLASH_RULE_TYPE_MAP,
    Entry,
    Inclusion,
    ParsedList,
    Processor,
    validate_domain_chars,
    validate_attr_chars,
    validate_site_name,
    is_match_attr_filters,
    _write_header,
    write_surge,
    write_clash,
    TARGET_BASE_PATH,
)


# ══════════════════════════════════════════════════════════════════════════════
# Validators
# ══════════════════════════════════════════════════════════════════════════════

class TestValidateDomainChars:
    def test_valid_simple(self):
        assert validate_domain_chars("example.com")

    def test_valid_hyphen(self):
        assert validate_domain_chars("my-host.example.com")

    def test_valid_digits(self):
        assert validate_domain_chars("123.456.com")

    def test_empty_string(self):
        assert not validate_domain_chars("")

    def test_uppercase_rejected(self):
        assert not validate_domain_chars("Example.com")

    def test_underscore_rejected(self):
        assert not validate_domain_chars("my_host.com")

    def test_space_rejected(self):
        assert not validate_domain_chars("my host.com")


class TestValidateAttrChars:
    def test_valid_lower(self):
        assert validate_attr_chars("vpn")

    def test_valid_with_bang(self):
        assert validate_attr_chars("vpn!")

    def test_empty_string(self):
        assert not validate_attr_chars("")

    def test_uppercase_rejected(self):
        assert not validate_attr_chars("VPN")

    def test_hyphen_rejected(self):
        assert not validate_attr_chars("vpn-x")

    def test_space_rejected(self):
        assert not validate_attr_chars("vpn x")


class TestValidateSiteName:
    def test_valid(self):
        assert validate_site_name("google")

    def test_valid_hyphen(self):
        assert validate_site_name("google-gemini")

    def test_valid_bang(self):
        assert validate_site_name("!cn")

    def test_empty_string(self):
        assert not validate_site_name("")

    def test_uppercase_rejected(self):
        assert not validate_site_name("Google")

    def test_dot_rejected(self):
        assert not validate_site_name("google.com")


# ══════════════════════════════════════════════════════════════════════════════
# is_match_attr_filters – core of the inclusion bug-fix
# ══════════════════════════════════════════════════════════════════════════════

def _make_entry(attrs: list[str]) -> Entry:
    return Entry(rule_type=RuleType.DOMAIN, value="example.com", attrs=attrs,
                 plain=f"domain:example.com")


def _make_filter(must: list[str] = (), ban: list[str] = ()) -> Inclusion:
    return Inclusion(source="src", must_attrs=list(must), ban_attrs=list(ban))


class TestIsMatchAttrFilters:
    # Entry with NO attrs --------------------------------------------------
    def test_no_attrs_no_filters(self):
        """Entry without attrs passes a filter with no must/ban."""
        assert is_match_attr_filters(_make_entry([]), _make_filter())

    def test_no_attrs_with_must(self):
        """Entry without attrs FAILS a filter that requires an attr."""
        assert not is_match_attr_filters(_make_entry([]), _make_filter(must=["vpn"]))

    def test_no_attrs_with_ban_only(self):
        """Entry without attrs PASSES a filter that only bans an attr (nothing to ban)."""
        assert is_match_attr_filters(_make_entry([]), _make_filter(ban=["ads"]))

    # Entry WITH attrs -----------------------------------------------------
    def test_attrs_no_filters(self):
        """Entry with attrs passes a filter with no must/ban."""
        assert is_match_attr_filters(_make_entry(["vpn"]), _make_filter())

    def test_attrs_must_present(self):
        """Entry must contain the required attr."""
        assert is_match_attr_filters(_make_entry(["vpn", "cn"]), _make_filter(must=["vpn"]))

    def test_attrs_must_absent(self):
        """Entry is rejected if a required attr is missing."""
        assert not is_match_attr_filters(_make_entry(["cn"]), _make_filter(must=["vpn"]))

    def test_attrs_ban_absent(self):
        """Entry passes when banned attr is not present."""
        assert is_match_attr_filters(_make_entry(["vpn"]), _make_filter(ban=["ads"]))

    def test_attrs_ban_present(self):
        """Entry is rejected when banned attr is present."""
        assert not is_match_attr_filters(_make_entry(["ads"]), _make_filter(ban=["ads"]))

    def test_attrs_must_and_ban_combined(self):
        """Entry must have 'vpn' and must NOT have 'ads'."""
        assert is_match_attr_filters(_make_entry(["vpn"]),
                                     _make_filter(must=["vpn"], ban=["ads"]))
        assert not is_match_attr_filters(_make_entry(["vpn", "ads"]),
                                         _make_filter(must=["vpn"], ban=["ads"]))

    def test_multiple_must_all_present(self):
        assert is_match_attr_filters(_make_entry(["a", "b"]), _make_filter(must=["a", "b"]))

    def test_multiple_must_one_missing(self):
        assert not is_match_attr_filters(_make_entry(["a"]), _make_filter(must=["a", "b"]))


# ══════════════════════════════════════════════════════════════════════════════
# Processor – parsing
# ══════════════════════════════════════════════════════════════════════════════

class TestProcessorParseLine:
    def setup_method(self):
        self.p = Processor()

    def test_bare_domain(self):
        rt, rule = self.p.parse_line("example.com")
        assert rt == RuleType.DOMAIN
        assert rule == "example.com"

    def test_typed_domain(self):
        rt, rule = self.p.parse_line("domain:example.com")
        assert rt == RuleType.DOMAIN
        assert rule == "example.com"

    def test_full_domain(self):
        rt, rule = self.p.parse_line("full:example.com")
        assert rt == RuleType.FULL_DOMAIN

    def test_keyword(self):
        rt, rule = self.p.parse_line("keyword:google")
        assert rt == RuleType.KEYWORD

    def test_regexp(self):
        rt, rule = self.p.parse_line("regexp:^example")
        assert rt == RuleType.REGEXP

    def test_include(self):
        rt, rule = self.p.parse_line("include:google")
        assert rt == RuleType.INCLUDE
        assert rule == "google"

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError):
            self.p.parse_line("bogus:example.com")


class TestProcessorParseAttribute:
    def setup_method(self):
        self.p = Processor()

    def test_regular_attr(self):
        name, is_ban = self.p.parse_attribute("vpn")
        assert name == "vpn" and not is_ban

    def test_ban_attr(self):
        name, is_ban = self.p.parse_attribute("-ads")
        assert name == "ads" and is_ban

    def test_invalid_attr_name_raises(self):
        with pytest.raises(ValueError, match="invalid attribute name"):
            self.p.parse_attribute("VPN")

    def test_invalid_ban_attr_raises(self):
        with pytest.raises(ValueError, match="invalid attribute name"):
            self.p.parse_attribute("-VPN")


class TestProcessorParseInclusion:
    def setup_method(self):
        self.p = Processor()

    def test_bare_source(self):
        inc = self.p.parse_inclusion("google")
        assert inc.source == "google"
        assert inc.must_attrs == []
        assert inc.ban_attrs == []

    def test_with_must_attr(self):
        inc = self.p.parse_inclusion("google @vpn")
        assert "vpn" in inc.must_attrs
        assert inc.ban_attrs == []

    def test_with_ban_attr(self):
        inc = self.p.parse_inclusion("google @-ads")
        assert "ads" in inc.ban_attrs
        assert inc.must_attrs == []

    def test_with_both(self):
        inc = self.p.parse_inclusion("google @vpn @-ads")
        assert "vpn" in inc.must_attrs
        assert "ads" in inc.ban_attrs

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty inclusion rule"):
            self.p.parse_inclusion("")

    def test_invalid_site_name_raises(self):
        # dots are not valid in site names (validate_site_name rejects them)
        with pytest.raises(ValueError, match="invalid site name"):
            self.p.parse_inclusion("google.com")

    def test_affiliation_in_inclusion_raises(self):
        with pytest.raises(ValueError, match="affiliation is not allowed"):
            self.p.parse_inclusion("google &other")

    def test_unknown_field_raises(self):
        with pytest.raises(ValueError, match="unknown field"):
            self.p.parse_inclusion("google !notvalid")


class TestProcessorParseEntry:
    def setup_method(self):
        self.p = Processor()

    def test_domain_entry(self):
        entry, affs = self.p.parse_entry(RuleType.DOMAIN, "example.com")
        assert entry.value == "example.com"
        assert entry.rule_type == RuleType.DOMAIN
        assert affs == []

    def test_full_domain_entry(self):
        entry, _ = self.p.parse_entry(RuleType.FULL_DOMAIN, "example.com")
        assert entry.rule_type == RuleType.FULL_DOMAIN

    def test_keyword_entry(self):
        entry, _ = self.p.parse_entry(RuleType.KEYWORD, "google")
        assert entry.rule_type == RuleType.KEYWORD

    def test_regexp_entry(self):
        entry, affs = self.p.parse_entry(RuleType.REGEXP, "^example")
        assert entry.rule_type == RuleType.REGEXP
        assert affs == []

    def test_attrs_parsed(self):
        entry, _ = self.p.parse_entry(RuleType.DOMAIN, "example.com @vpn")
        assert "vpn" in entry.attrs

    def test_affiliations_parsed(self):
        entry, affs = self.p.parse_entry(RuleType.DOMAIN, "example.com &other")
        assert "other" in affs

    def test_empty_rule_raises(self):
        with pytest.raises(ValueError, match="empty entry rule"):
            self.p.parse_entry(RuleType.DOMAIN, "")

    def test_invalid_domain_raises(self):
        with pytest.raises(ValueError, match="invalid domain"):
            self.p.parse_entry(RuleType.DOMAIN, "Example.com")

    def test_invalid_attr_raises(self):
        # hyphens are invalid in attr names (only ! is a special char)
        with pytest.raises(ValueError, match="invalid attribute name"):
            self.p.parse_entry(RuleType.DOMAIN, "example.com @my-attr")

    def test_plain_field_populated(self):
        entry, _ = self.p.parse_entry(RuleType.DOMAIN, "example.com @vpn")
        assert entry.plain == "domain:example.com:@vpn"


# ══════════════════════════════════════════════════════════════════════════════
# Processor.load_data
# ══════════════════════════════════════════════════════════════════════════════

class TestLoadData:
    def setup_method(self):
        self.p = Processor()

    def _write(self, tmp_path: pathlib.Path, content: str) -> pathlib.Path:
        f = tmp_path / "testlist"
        f.write_text(textwrap.dedent(content))
        return f

    def test_basic_domain(self, tmp_path):
        f = self._write(tmp_path, "example.com\n")
        self.p.load_data("testlist", f)
        pl = self.p.parsed_list_map["testlist"]
        assert len(pl.entries) == 1
        assert pl.entries[0].value == "example.com"

    def test_comment_ignored(self, tmp_path):
        f = self._write(tmp_path, "# this is a comment\nexample.com\n")
        self.p.load_data("testlist", f)
        assert len(self.p.parsed_list_map["testlist"].entries) == 1

    def test_inline_comment_stripped(self, tmp_path):
        f = self._write(tmp_path, "example.com # inline comment\n")
        self.p.load_data("testlist", f)
        assert self.p.parsed_list_map["testlist"].entries[0].value == "example.com"

    def test_blank_lines_ignored(self, tmp_path):
        f = self._write(tmp_path, "\n\nexample.com\n\n")
        self.p.load_data("testlist", f)
        assert len(self.p.parsed_list_map["testlist"].entries) == 1

    def test_inclusion_parsed(self, tmp_path):
        f = self._write(tmp_path, "include:google\n")
        self.p.load_data("testlist", f)
        pl = self.p.parsed_list_map["testlist"]
        assert len(pl.inclusions) == 1
        assert pl.inclusions[0].source == "google"

    def test_inclusion_with_attrs_parsed(self, tmp_path):
        f = self._write(tmp_path, "include:google @vpn\n")
        self.p.load_data("testlist", f)
        inc = self.p.parsed_list_map["testlist"].inclusions[0]
        assert "vpn" in inc.must_attrs

    def test_affiliation_shared_entry(self, tmp_path):
        """An entry with an affiliation appears in BOTH the parent and affiliated lists."""
        f = self._write(tmp_path, "example.com &other\n")
        self.p.load_data("testlist", f)
        assert "other" in self.p.parsed_list_map
        assert self.p.parsed_list_map["other"].entries[0].value == "example.com"

    def test_invalid_line_raises_with_context(self, tmp_path):
        f = self._write(tmp_path, "example.com\nExample.COM\n")
        with pytest.raises(ValueError) as exc:
            self.p.load_data("testlist", f)
        assert "testlist" in str(exc.value)  # file path included
        assert ":2:" in str(exc.value)        # line number included


# ══════════════════════════════════════════════════════════════════════════════
# Processor.polish_list
# ══════════════════════════════════════════════════════════════════════════════

def _entry(rule_type: RuleType, value: str, attrs=()) -> Entry:
    e = Entry(rule_type=rule_type, value=value, attrs=list(attrs))
    p = Processor()
    e.plain = p.plain(e)
    return e


class TestPolishList:
    def setup_method(self):
        self.p = Processor()

    def test_redundant_subdomain_removed(self):
        """full:sub.example.com is redundant if example.com is already present."""
        parent = _entry(RuleType.DOMAIN, "example.com")
        sub = _entry(RuleType.FULL_DOMAIN, "sub.example.com")
        rough = {e.plain: e for e in [parent, sub]}
        result = self.p.polish_list(rough)
        values = [e.value for e in result]
        assert "example.com" in values
        assert "sub.example.com" not in values

    def test_non_redundant_subdomain_kept(self):
        sub = _entry(RuleType.DOMAIN, "sub.example.com")
        rough = {sub.plain: sub}
        result = self.p.polish_list(rough)
        assert result[0].value == "sub.example.com"

    def test_entry_with_attrs_kept_even_if_redundant_parent(self):
        """Entries with attrs are never considered redundant."""
        parent = _entry(RuleType.DOMAIN, "example.com")
        tagged = _entry(RuleType.DOMAIN, "sub.example.com", attrs=["vpn"])
        rough = {e.plain: e for e in [parent, tagged]}
        result = self.p.polish_list(rough)
        assert any(e.value == "sub.example.com" for e in result)

    def test_keywords_always_kept(self):
        kw = _entry(RuleType.KEYWORD, "google")
        rough = {kw.plain: kw}
        result = self.p.polish_list(rough)
        assert result[0].rule_type == RuleType.KEYWORD

    def test_regexps_always_kept(self):
        rx = _entry(RuleType.REGEXP, "^example")
        rough = {rx.plain: rx}
        result = self.p.polish_list(rough)
        assert result[0].rule_type == RuleType.REGEXP

    def test_result_is_sorted(self):
        a = _entry(RuleType.DOMAIN, "z.com")
        b = _entry(RuleType.DOMAIN, "a.com")
        rough = {e.plain: e for e in [a, b]}
        result = self.p.polish_list(rough)
        plains = [e.plain for e in result]
        assert plains == sorted(plains)


# ══════════════════════════════════════════════════════════════════════════════
# Processor.resolve – including the inclusion-filter bug-fix verification
# ══════════════════════════════════════════════════════════════════════════════

def _build_processor_with_lists(lists: dict[str, str]) -> Processor:
    """
    Build a Processor from a dict of {name: file_content} using tmp files.
    """
    import tempfile, os
    p = Processor()
    tmpdir = pathlib.Path(tempfile.mkdtemp())
    for name, content in lists.items():
        f = tmpdir / name
        f.write_text(textwrap.dedent(content))
        p.load_data(name, f)
    return p


class TestResolve:
    def test_simple_list(self):
        p = _build_processor_with_lists({"base": "example.com\n"})
        p.resolve("base")
        assert "base" in p.final_map
        assert p.final_map["base"][0].value == "example.com"

    def test_circular_inclusion_raises(self):
        p = _build_processor_with_lists({
            "a": "include:b\nexample.com\n",
            "b": "include:a\nother.com\n",
        })
        with pytest.raises(ValueError, match="circular inclusion"):
            p.resolve("a")

    def test_circular_inclusion_cleans_up_set(self):
        """After a circular-inclusion error the set must not retain stale entries."""
        p = _build_processor_with_lists({
            "a": "include:b\nexample.com\n",
            "b": "include:a\nother.com\n",
        })
        with pytest.raises(ValueError):
            p.resolve("a")
        assert "a" not in p.circular_inclusion_map
        assert "b" not in p.circular_inclusion_map

    def test_list_not_found_raises(self):
        p = Processor()
        with pytest.raises(ValueError, match="list not found"):
            p.resolve("nonexistent")

    def test_empty_list_raises(self):
        """A list that resolves to zero entries raises."""
        p = _build_processor_with_lists({"empty": ""})
        with pytest.raises(ValueError, match="empty list"):
            p.resolve("empty")

    def test_inclusion_no_filter_passes_all(self):
        """When must_attrs and ban_attrs are both empty, all entries pass."""
        p = _build_processor_with_lists({
            "src": "example.com @vpn\nother.com\n",
            "dst": "include:src\n",
        })
        p.resolve("src")
        p.resolve("dst")
        values = {e.value for e in p.final_map["dst"]}
        assert "example.com" in values
        assert "other.com" in values

    def test_inclusion_must_attr_filters_correctly(self):
        """
        BUG-FIX VERIFICATION:
        With only must_attrs set, entries WITHOUT the required attr must be excluded.
        The old code (or) would have incorrectly passed all entries; the new code (and)
        correctly applies the filter.
        """
        p = _build_processor_with_lists({
            "src": "example.com @vpn\nother.com\n",
            "dst": "include:src @vpn\n",  # only want entries tagged @vpn
        })
        p.resolve("src")
        p.resolve("dst")
        values = {e.value for e in p.final_map["dst"]}
        # example.com has @vpn → should be included
        assert "example.com" in values
        # other.com has no attrs → must NOT be included
        assert "other.com" not in values

    def test_inclusion_ban_attr_filters_correctly(self):
        """
        BUG-FIX VERIFICATION:
        With only ban_attrs set, entries WITH the banned attr must be excluded.
        The old code (or) would have incorrectly passed all entries because must was empty.
        """
        p = _build_processor_with_lists({
            "src": "example.com @ads\nother.com\n",
            "dst": "include:src @-ads\n",  # exclude entries tagged @ads
        })
        p.resolve("src")
        p.resolve("dst")
        values = {e.value for e in p.final_map["dst"]}
        # example.com has @ads → must NOT be included
        assert "example.com" not in values
        # other.com has no attrs → should pass through (no attrs, no banned)
        assert "other.com" in values

    def test_inclusion_resolved_once_cached(self):
        """Resolving the same list twice should use the cached result."""
        p = _build_processor_with_lists({"base": "example.com\n"})
        p.resolve("base")
        result1 = p.final_map["base"]
        p.resolve("base")  # second call should be no-op
        assert p.final_map["base"] is result1

    def test_deep_inclusion_chain(self):
        """A → B → C chain should resolve correctly."""
        p = _build_processor_with_lists({
            "c": "leaf.com\n",
            "b": "include:c\nmid.com\n",
            "a": "include:b\ntop.com\n",
        })
        p.resolve("a")
        values = {e.value for e in p.final_map["a"]}
        assert {"leaf.com", "mid.com", "top.com"}.issubset(values)


# ══════════════════════════════════════════════════════════════════════════════
# Rule-type maps
# ══════════════════════════════════════════════════════════════════════════════

class TestRuleTypeMaps:
    def test_surge_map_covers_expected_types(self):
        assert RuleType.DOMAIN in SURGE_RULE_TYPE_MAP
        assert RuleType.FULL_DOMAIN in SURGE_RULE_TYPE_MAP
        assert RuleType.KEYWORD in SURGE_RULE_TYPE_MAP
        # REGEXP should NOT be in the map (handled specially as a comment)
        assert RuleType.REGEXP not in SURGE_RULE_TYPE_MAP

    def test_clash_map_covers_regexp(self):
        assert RuleType.REGEXP in CLASH_RULE_TYPE_MAP

    def test_surge_domain_suffix(self):
        assert SURGE_RULE_TYPE_MAP[RuleType.DOMAIN] == "DOMAIN-SUFFIX"

    def test_surge_full_domain(self):
        assert SURGE_RULE_TYPE_MAP[RuleType.FULL_DOMAIN] == "DOMAIN"

    def test_clash_regexp(self):
        assert CLASH_RULE_TYPE_MAP[RuleType.REGEXP] == "DOMAIN-REGEXP"


# ══════════════════════════════════════════════════════════════════════════════
# Writers
# ══════════════════════════════════════════════════════════════════════════════

class TestWriteHeader:
    def test_header_contains_url(self, tmp_path):
        f = (tmp_path / "out.txt").open("w")
        _write_header(f, "surge", "test.txt", 42)
        f.close()
        content = (tmp_path / "out.txt").read_text()
        assert "surge/test.txt" in content
        assert "# Total: 42" in content
        assert "# Name: test" in content


def _entries_for_writer() -> list[Entry]:
    p = Processor()
    entries = []
    for rt, val in [
        (RuleType.DOMAIN, "example.com"),
        (RuleType.FULL_DOMAIN, "full.example.com"),
        (RuleType.KEYWORD, "testkey"),
        (RuleType.REGEXP, "^test"),
    ]:
        e = Entry(rule_type=rt, value=val)
        e.plain = p.plain(e)
        entries.append(e)
    return entries


class TestWriteSurge:
    def test_creates_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr("main.TARGET_BASE_PATH", tmp_path)
        (tmp_path / "surge").mkdir()
        write_surge("test.txt", _entries_for_writer())
        assert (tmp_path / "surge" / "test.txt").exists()

    def test_domain_suffix_written(self, tmp_path, monkeypatch):
        monkeypatch.setattr("main.TARGET_BASE_PATH", tmp_path)
        (tmp_path / "surge").mkdir()
        write_surge("test.txt", _entries_for_writer())
        content = (tmp_path / "surge" / "test.txt").read_text()
        assert "DOMAIN-SUFFIX,example.com" in content

    def test_full_domain_written(self, tmp_path, monkeypatch):
        monkeypatch.setattr("main.TARGET_BASE_PATH", tmp_path)
        (tmp_path / "surge").mkdir()
        write_surge("test.txt", _entries_for_writer())
        content = (tmp_path / "surge" / "test.txt").read_text()
        assert "DOMAIN,full.example.com" in content

    def test_keyword_written(self, tmp_path, monkeypatch):
        monkeypatch.setattr("main.TARGET_BASE_PATH", tmp_path)
        (tmp_path / "surge").mkdir()
        write_surge("test.txt", _entries_for_writer())
        content = (tmp_path / "surge" / "test.txt").read_text()
        assert "DOMAIN-KEYWORD,testkey" in content

    def test_regexp_as_comment(self, tmp_path, monkeypatch):
        monkeypatch.setattr("main.TARGET_BASE_PATH", tmp_path)
        (tmp_path / "surge").mkdir()
        write_surge("test.txt", _entries_for_writer())
        content = (tmp_path / "surge" / "test.txt").read_text()
        assert "# REGEXP,^test" in content
        # Must NOT appear as an active rule
        assert "DOMAIN-REGEXP" not in content


class TestWriteClash:
    def test_creates_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr("main.TARGET_BASE_PATH", tmp_path)
        (tmp_path / "clash").mkdir()
        write_clash("test.txt", _entries_for_writer())
        assert (tmp_path / "clash" / "test.txt").exists()

    def test_domain_suffix_written(self, tmp_path, monkeypatch):
        monkeypatch.setattr("main.TARGET_BASE_PATH", tmp_path)
        (tmp_path / "clash").mkdir()
        write_clash("test.txt", _entries_for_writer())
        content = (tmp_path / "clash" / "test.txt").read_text()
        assert "DOMAIN-SUFFIX,example.com" in content

    def test_regexp_written_as_rule(self, tmp_path, monkeypatch):
        monkeypatch.setattr("main.TARGET_BASE_PATH", tmp_path)
        (tmp_path / "clash").mkdir()
        write_clash("test.txt", _entries_for_writer())
        content = (tmp_path / "clash" / "test.txt").read_text()
        assert "DOMAIN-REGEXP,^test" in content


# ══════════════════════════════════════════════════════════════════════════════
# Integration: full pipeline with mock data
# ══════════════════════════════════════════════════════════════════════════════

class TestIntegration:
    """End-to-end pipeline: load → resolve → write, using mock domain-list files."""

    def test_simple_pipeline(self, tmp_path, monkeypatch):
        import main as m
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        dist_dir = tmp_path / "dist"
        monkeypatch.setattr(m, "TARGET_BASE_PATH", dist_dir)

        (src_dir / "mylist").write_text("example.com\nfull:sub.example.com\n")

        p = Processor()
        p.load_data("mylist", src_dir / "mylist")
        p.resolve("mylist")

        (dist_dir / "surge").mkdir(parents=True)
        (dist_dir / "clash").mkdir(parents=True)

        write_surge("mylist.txt", p.final_map["mylist"])
        write_clash("mylist.txt", p.final_map["mylist"])

        surge = (dist_dir / "surge" / "mylist.txt").read_text()
        clash = (dist_dir / "clash" / "mylist.txt").read_text()

        # sub.example.com is a full subdomain of example.com → should be deduped
        assert "DOMAIN-SUFFIX,example.com" in surge
        assert "DOMAIN,sub.example.com" not in surge

        assert "DOMAIN-SUFFIX,example.com" in clash

    def test_inclusion_pipeline_with_filter(self, tmp_path, monkeypatch):
        """
        Full pipeline: src has entries with/without attrs; dst includes src with @vpn filter.
        Only the @vpn-tagged entry should appear in dst's output.
        """
        import main as m
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        dist_dir = tmp_path / "dist"
        monkeypatch.setattr(m, "TARGET_BASE_PATH", dist_dir)

        (src_dir / "src").write_text("vpn.example.com @vpn\nopen.example.com\n")
        (src_dir / "dst").write_text("include:src @vpn\n")

        p = Processor()
        for name in ["src", "dst"]:
            p.load_data(name, src_dir / name)
        p.resolve("src")
        p.resolve("dst")

        (dist_dir / "surge").mkdir(parents=True)
        (dist_dir / "clash").mkdir(parents=True)

        write_surge("dst.txt", p.final_map["dst"])
        content = (dist_dir / "surge" / "dst.txt").read_text()

        assert "vpn.example.com" in content
        assert "open.example.com" not in content


# ══════════════════════════════════════════════════════════════════════════════
# Additional coverage: parse_entry edge cases and main()
# ══════════════════════════════════════════════════════════════════════════════

class TestParseEntryEdgeCases:
    def setup_method(self):
        self.p = Processor()

    def test_invalid_affiliation_name_raises(self):
        """Affiliation names with dots (invalid chars) must raise."""
        with pytest.raises(ValueError, match="invalid affiliation name"):
            self.p.parse_entry(RuleType.DOMAIN, "example.com &bad.aff")

    def test_unknown_field_in_entry_raises(self):
        """Fields that are neither @attr nor &aff are rejected."""
        with pytest.raises(ValueError, match="unknown field"):
            self.p.parse_entry(RuleType.DOMAIN, "example.com unknownfield")


class TestMainFunction:
    """Test the main() entry point with monkeypatched paths."""

    def test_main_runs_with_mock_data(self, tmp_path, monkeypatch):
        import main as m
        src_dir = tmp_path / "data"
        src_dir.mkdir()
        dist_dir = tmp_path / "dist"

        (src_dir / "mylist").write_text("example.com\nother.org\n")

        monkeypatch.setattr(m, "SOURCE_BASE_PATH", src_dir)
        monkeypatch.setattr(m, "TARGET_BASE_PATH", dist_dir)

        m.main()

        assert (dist_dir / "surge" / "mylist.txt").exists()
        assert (dist_dir / "clash" / "mylist.txt").exists()
        assert (dist_dir / "quickstart.txt").exists()

    def test_main_bang_name_converted(self, tmp_path, monkeypatch):
        """Names containing '!' become 'non-' in output file names."""
        import main as m
        src_dir = tmp_path / "data"
        src_dir.mkdir()
        dist_dir = tmp_path / "dist"

        (src_dir / "!cn").write_text("example.cn\n")

        monkeypatch.setattr(m, "SOURCE_BASE_PATH", src_dir)
        monkeypatch.setattr(m, "TARGET_BASE_PATH", dist_dir)

        m.main()

        assert (dist_dir / "surge" / "non-cn.txt").exists()
        assert (dist_dir / "clash" / "non-cn.txt").exists()

    def test_main_skips_invalid_filenames(self, tmp_path, monkeypatch):
        """Files whose names don't pass validate_site_name are ignored."""
        import main as m
        src_dir = tmp_path / "data"
        src_dir.mkdir()
        dist_dir = tmp_path / "dist"

        (src_dir / "valid").write_text("example.com\n")
        (src_dir / "Invalid.txt").write_text("other.com\n")  # uppercase -> ignored

        monkeypatch.setattr(m, "SOURCE_BASE_PATH", src_dir)
        monkeypatch.setattr(m, "TARGET_BASE_PATH", dist_dir)

        m.main()

        assert (dist_dir / "surge" / "valid.txt").exists()
        assert not (dist_dir / "surge" / "Invalid.txt.txt").exists()

    def test_main_quickstart_contains_list_table(self, tmp_path, monkeypatch):
        import main as m
        src_dir = tmp_path / "data"
        src_dir.mkdir()
        dist_dir = tmp_path / "dist"

        (src_dir / "alpha").write_text("alpha.com\n")
        (src_dir / "beta").write_text("beta.com\n")

        monkeypatch.setattr(m, "SOURCE_BASE_PATH", src_dir)
        monkeypatch.setattr(m, "TARGET_BASE_PATH", dist_dir)

        m.main()

        quickstart = (dist_dir / "quickstart.txt").read_text()
        assert "alpha" in quickstart
        assert "beta" in quickstart
        assert "surge" in quickstart
        assert "clash" in quickstart
