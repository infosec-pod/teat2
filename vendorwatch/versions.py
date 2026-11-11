"""Version comparison and "does this CVE affect the versions I run?" logic.

Handles the two places affected-version data comes from:

* NVD CPE configurations (``cpeMatch`` entries with versionStart/End ranges)
* CVE.org / CNA records (``affected[].versions`` with ``lessThan`` etc.)

and a last-resort heuristic that reads ranges out of the description text
("FortiOS 7.4.0 through 7.4.2", "versions prior to 2.3.1").
"""
from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field

_PRE = {"dev", "alpha", "beta", "pre", "preview", "rc"}


def _key(version: str) -> list[tuple]:
    parts = re.findall(r"\d+|[A-Za-z]+", version or "")
    key = []
    for p in parts:
        if p.isdigit():
            key.append((1, int(p)))
        elif p.lower() in _PRE and key:  # pre-release marker after a number
            key.append((-1, p.lower()))
        elif p.lower() in {"v", "version", "build"} and not key:
            continue
        else:
            key.append((2, p.lower()))
    return key


def compare(a: str, b: str) -> int:
    """Return -1, 0, 1 like cmp(a, b). ``7.4`` == ``7.4.0``; ``7.4.3a`` > ``7.4.3``; ``1.0rc1`` < ``1.0``."""
    ka, kb = _key(a), _key(b)
    n = max(len(ka), len(kb))
    ka += [(1, 0)] * (n - len(ka))
    kb += [(1, 0)] * (n - len(kb))
    return (ka > kb) - (ka < kb)


version_sort_key = functools.cmp_to_key(compare)


@dataclass
class Range:
    start_incl: str | None = None
    start_excl: str | None = None
    end_incl: str | None = None
    end_excl: str | None = None
    exact: str | None = None

    def contains(self, v: str) -> bool:
        if self.exact is not None:
            return compare(v, self.exact) == 0
        if self.start_incl and compare(v, self.start_incl) < 0:
            return False
        if self.start_excl and compare(v, self.start_excl) <= 0:
            return False
        if self.end_incl and compare(v, self.end_incl) > 0:
            return False
        if self.end_excl and compare(v, self.end_excl) >= 0:
            return False
        return True

    @property
    def fixed_in(self) -> str | None:
        return self.end_excl

    def __str__(self) -> str:
        if self.exact:
            return f"= {self.exact}"
        lo = f">= {self.start_incl}" if self.start_incl else (f"> {self.start_excl}" if self.start_excl else "")
        hi = f"<= {self.end_incl}" if self.end_incl else (f"< {self.end_excl}" if self.end_excl else "")
        return ", ".join(x for x in (lo, hi) if x) or "all versions"


@dataclass
class Impact:
    """Result of checking one CVE against one asset."""

    affected: bool | None              # True / False / None (unknown)
    source: str = ""                   # nvd | cna | description | none
    affected_versions: list[str] = field(default_factory=list)  # which of YOUR versions are hit
    fixed_versions: list[str] = field(default_factory=list)     # earliest fix in the matching branch
    ranges: list[str] = field(default_factory=list)             # human readable vulnerable ranges
    product_match: bool = False        # the CVE names this product at all
    raw_ranges: list[Range] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict:
        return {
            "affected": self.affected,
            "source": self.source,
            "affected_versions": self.affected_versions,
            "fixed_versions": self.fixed_versions,
            "ranges": self.ranges,
            "raw_ranges": [vars(r) for r in self.raw_ranges],
        }


def _cpe_fields(cpe: str) -> list[str]:
    # cpe:2.3:part:vendor:product:version:update:...
    parts = cpe.split(":")
    return parts + ["*"] * (13 - len(parts))


def _cpe_matches_asset(cpe: str, vendor: str, product: str, part: str) -> bool:
    f = _cpe_fields(cpe)
    return (
        f[3].lower() == vendor
        and f[4].lower() == product
        and (part in ("*", "") or f[2].lower() == part)
    )


def nvd_ranges(cve: dict, vendor: str, product: str, part: str = "*") -> list[Range]:
    """Extract vulnerable ranges for vendor:product from an NVD 2.0 ``cve`` object."""
    ranges: list[Range] = []

    def walk(nodes):
        for node in nodes or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable", False):
                    continue
                crit = m.get("criteria", "")
                if not _cpe_matches_asset(crit, vendor, product, part):
                    continue
                ver = _cpe_fields(crit)[5]
                if ver not in ("*", "-", ""):
                    upd = _cpe_fields(crit)[6]
                    exact = ver if upd in ("*", "-", "") else f"{ver}{upd}"
                    ranges.append(Range(exact=exact))
                else:
                    ranges.append(
                        Range(
                            start_incl=m.get("versionStartIncluding"),
                            start_excl=m.get("versionStartExcluding"),
                            end_incl=m.get("versionEndIncluding"),
                            end_excl=m.get("versionEndExcluding"),
                        )
                    )
            walk(node.get("children"))

    for conf in cve.get("configurations", []) or []:
        walk(conf.get("nodes"))
    return ranges


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def cna_ranges(record: dict, vendor: str, product: str, part: str = "*", aliases: list[str] | None = None) -> list[Range]:
    """Extract vulnerable ranges from a CVE JSON 5 record (cveawg.mitre.org)."""
    ranges: list[Range] = []
    cna = (record.get("containers") or {}).get("cna") or {}
    names = {_norm(product)} | {_norm(a) for a in (aliases or []) if a}
    names.discard("")
    for aff in cna.get("affected", []) or []:
        cpes = aff.get("cpes") or []
        cpe_hit = [c for c in cpes if _cpe_matches_asset(c, vendor, product, part)]
        name_hit = _norm(aff.get("vendor", "")) .startswith(_norm(vendor)) and _norm(aff.get("product", "")) in names
        if not (cpe_hit or name_hit):
            continue
        got_any = False
        for v in aff.get("versions", []) or []:
            if v.get("status", "affected") != "affected":
                continue
            base = str(v.get("version", ""))
            if v.get("lessThan") or v.get("lessThanOrEqual"):
                lt, lte = v.get("lessThan"), v.get("lessThanOrEqual")
                start = base if base not in ("", "0", "*", "n/a", "unspecified") else None
                ranges.append(
                    Range(
                        start_incl=start,
                        end_excl=None if (lt in (None, "*")) else lt,
                        end_incl=None if (lte in (None, "*")) else lte,
                    )
                )
                got_any = True
            elif base and base not in ("*", "n/a", "unspecified"):
                ranges.append(Range(exact=base))
                got_any = True
        if not got_any:
            for c in cpe_hit:
                ver = _cpe_fields(c)[5]
                if ver not in ("*", "-", ""):
                    ranges.append(Range(exact=ver))
    return ranges


_V = r"\d+(?:\.\d+)+[a-z0-9.\-]*"
_VER = r"v?(" + _V + r")"
_THROUGH = re.compile(_VER + r"\s+(?:through|to|thru|-)\s+" + _VER, re.I)
_BEFORE = re.compile(r"(?:before|prior to|earlier than|below|<)\s+(?:versions?\s+)?(v?" + _V
                     + r"(?:\s*(?:,|and|or)\s*v?" + _V + r")*)", re.I)
_VER_ONLY = re.compile(_VER, re.I)
_AND_EARLIER = re.compile(_VER + r"\s+(?:and|or)\s+(?:earlier|below|prior)", re.I)


def description_ranges(text: str) -> list[Range]:
    """Very rough fallback: pull version ranges out of free text."""
    ranges: list[Range] = []
    for a, b in _THROUGH.findall(text or ""):
        ranges.append(Range(start_incl=a, end_incl=b))
    for group in _BEFORE.findall(text or ""):
        for b in _VER_ONLY.findall(group):
            ranges.append(Range(end_excl=b.rstrip(".,")))
    for b in _AND_EARLIER.findall(text or ""):
        ranges.append(Range(end_incl=b))
    return ranges


def _same_branch(a: str, b: str) -> bool:
    ka, kb = _key(a)[:2], _key(b)[:2]
    return ka == kb


def evaluate(ranges: list[Range], my_versions: list[str], source: str) -> Impact:
    imp = Impact(affected=None, source=source, ranges=[str(r) for r in ranges], product_match=bool(ranges),
                 raw_ranges=list(ranges))
    if not ranges:
        imp.source = "none"
        return imp
    if not my_versions:
        return imp  # product is affected, but we don't know what you run
    hit = []
    fixes = set()
    for v in my_versions:
        matching = [r for r in ranges if r.contains(v)]
        if matching:
            hit.append(v)
            for r in matching:
                if r.fixed_in:
                    fixes.add(r.fixed_in)
            if not any(r.fixed_in for r in matching):
                # e.g. "7.4.0 through 7.4.2" -> look for any exclusive end in the same branch above v
                cands = [r.end_excl for r in ranges if r.end_excl and compare(r.end_excl, v) > 0 and _same_branch(r.end_excl, v)]
                if cands:
                    fixes.add(min(cands, key=version_sort_key))
    imp.affected = bool(hit)
    imp.affected_versions = hit
    imp.fixed_versions = sorted(fixes, key=version_sort_key)
    if source == "description" and imp.affected is False:
        imp.affected = None  # description parsing is fuzzy: never claim "not affected" from it
    return imp


def _fill_fix_from_text(imp: Impact, desc: str) -> Impact:
    """Exact-version CPE lists carry no "fixed in"; recover it from "before 22.7R2.5" style text."""
    if imp.affected and not imp.fixed_versions and desc:
        ends = [r.end_excl for r in description_ranges(desc) if r.end_excl]
        fixes = set()
        for v in imp.affected_versions:
            cands = [e for e in ends if compare(e, v) > 0 and _same_branch(e, v)]
            if cands:
                fixes.add(min(cands, key=version_sort_key))
        imp.fixed_versions = sorted(fixes, key=version_sort_key)
    return imp


def reassess(stored: dict, my_versions: list[str], description: str = "") -> Impact:
    """Re-run an assessment from a stored ``Impact.to_dict()`` (e.g. after you upgrade)."""
    src = stored.get("source", "none")
    raw = [Range(**r) for r in stored.get("raw_ranges") or []]
    if not raw:
        return Impact(affected=stored.get("affected") if src == "nvd-other-product" else None, source=src)
    return _fill_fix_from_text(evaluate(raw, my_versions, src), description)


def assess(
    nvd_cve: dict | None,
    cna_record: dict | None,
    vendor: str,
    product: str,
    part: str,
    my_versions: list[str],
    aliases: list[str] | None = None,
) -> Impact:
    """Best-available impact assessment: NVD config -> CNA record -> description text."""
    desc = ""
    if nvd_cve:
        desc = next((d["value"] for d in nvd_cve.get("descriptions", []) if d.get("lang") == "en"), "")
    elif cna_record:
        cna = (cna_record.get("containers") or {}).get("cna") or {}
        desc = next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "en").startswith("en")), "")

    if nvd_cve:
        r = nvd_ranges(nvd_cve, vendor, product, part)
        if r:
            return _fill_fix_from_text(evaluate(r, my_versions, "nvd"), desc)
        if nvd_cve.get("configurations"):
            # NVD has analysed this CVE and your product isn't in the vulnerable configuration
            return Impact(affected=False, source="nvd-other-product")
    if cna_record:
        r = cna_ranges(cna_record, vendor, product, part, aliases)
        if r:
            return _fill_fix_from_text(evaluate(r, my_versions, "cna"), desc)
        if ((cna_record.get("containers") or {}).get("cna") or {}).get("affected"):
            # CNA lists other products; naming can differ, so stay "unknown" but flag it
            return Impact(affected=None, source="cna-other-product")
    r = description_ranges(desc)
    if r:
        return evaluate(r, my_versions, "description")
    return Impact(affected=None, source="none")
