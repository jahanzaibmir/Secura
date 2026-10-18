"""Software composition analysis: known vulnerabilities in third-party dependencies."""
from __future__ import annotations

from collections import defaultdict

from backend.config import Settings
from backend.engines.base import Engine, EngineContext, EngineResult
from backend.engines.dependencies.models import Dependency
from backend.engines.dependencies.osv import Advisory, OSVClient, OSVError
from backend.engines.dependencies.parsers import has_sibling_lock, parse_manifest
from backend.engines.inventory import KIND_MANIFEST, Inventory, read_text
from backend.schemas import Finding

_MAX_DEPENDENCIES = 5000


class DependencyEngine(Engine):
    name = "dependencies"
    label = "Dependencies"
    description = "Checks pinned dependencies in lockfiles against the OSV vulnerability database."

    def availability(self, settings: Settings) -> tuple[bool, str]:
        if not settings.dependency_audit:
            return False, "Disabled (SECURA_DEPENDENCY_AUDIT=0)."
        return True, ""

    def applies(self, inventory: Inventory) -> bool:
        return bool(inventory.of_kind(KIND_MANIFEST))

    def run(self, context: EngineContext) -> EngineResult:
        result = EngineResult()
        manifests = context.inventory.of_kind(KIND_MANIFEST)
        all_paths = [m.rel for m in manifests]

        dependencies: dict[tuple, Dependency] = {}
        for manifest in manifests:
            if manifest.name.lower() == "package.json" and has_sibling_lock(manifest.rel, all_paths):
                continue
            text = read_text(manifest)
            if text is None:
                continue
            for dependency in parse_manifest(manifest.rel, text):
                dependencies.setdefault(dependency.key, dependency)

        unique = list(dependencies.values())[:_MAX_DEPENDENCIES]
        if not unique:
            result.notes.append(
                "Dependency manifests were found, but none pin exact versions. "
                "Commit a lockfile so dependencies can be audited precisely.")
            result.detail = "No pinned dependencies"
            return result

        context.token.raise_if_cancelled()
        context.progress(f"Querying OSV for {len(unique)} package(s)", 0.2)
        client = OSVClient(context.settings.osv_api_url, context.settings.osv_timeout)
        try:
            affected = client.affected(unique)
            context.token.raise_if_cancelled()
            context.progress("Fetching advisory details", 0.6)
            advisories = client.advisories(
                vuln_id for ids in affected.values() for vuln_id in _prefer_ghsa(ids)
            )
        except OSVError as exc:
            result.notes.append(f"Dependency audit skipped: {exc}.")
            result.detail = "OSV unavailable"
            return result

        vulnerable_packages = 0
        for index, ids in affected.items():
            dependency = unique[index]
            reported = self._findings_for(dependency, _prefer_ghsa(ids), advisories)
            if reported:
                vulnerable_packages += 1
                result.findings.extend(reported)

        result.detail = f"{len(unique)} package(s), {vulnerable_packages} vulnerable"
        return result

    @staticmethod
    def _findings_for(
        dependency: Dependency, vuln_ids: list[str], advisories: dict[str, Advisory],
    ) -> list[Finding]:
        findings: list[Finding] = []
        covered: set = set()
        for vuln_id in vuln_ids:
            advisory = advisories.get(vuln_id)
            if advisory is None or vuln_id in covered:
                continue
            covered.update({vuln_id, *advisory.aliases})
            fixed = advisory.fixed_for(dependency)
            remedy = f"Upgrade to {fixed} or later." if fixed else "No fixed release is listed yet."
            metadata = {
                "package": dependency.name,
                "version": dependency.version,
                "ecosystem": dependency.ecosystem,
                "advisory": advisory.display_id,
            }
            if fixed:
                metadata["fixed_version"] = fixed
            if advisory.cvss_score is not None:
                metadata["cvss"] = f"{advisory.cvss_score:.1f}"
            findings.append(Finding(
                engine="dependencies",
                rule_id=advisory.display_id,
                title=f"Vulnerable dependency: {dependency.name} {dependency.version}",
                description=f"{advisory.summary} ({advisory.display_id}). {remedy}",
                severity=advisory.severity,
                confidence=0.9,
                file_path=dependency.manifest,
                line=dependency.line,
                snippet=f"{dependency.name}=={dependency.version}  ({dependency.ecosystem})",
                cwe=advisory.cwe,
                references=advisory.references,
                metadata=metadata,
            ))
        return findings


def _prefer_ghsa(ids: list[str]) -> list[str]:
    """GitHub advisories carry curated severities, so they are evaluated first."""
    grouped = defaultdict(list)
    for vuln_id in ids:
        grouped[0 if vuln_id.startswith("GHSA-") else 1].append(vuln_id)
    return grouped[0] + grouped[1]
