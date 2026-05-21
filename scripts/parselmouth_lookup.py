"""Client for consuming public Parselmouth conda→PyPI mappings."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx

from scripts.purl_inference import normalize_purl, normalize_pypi_name

DEFAULT_BASE_URL = "https://conda-mapping.prefix.dev"


@dataclass(frozen=True)
class ParselmouthMapping:
    """A single Parselmouth hash-v0 mapping entry."""

    pypi_normalized_names: list[str]
    versions: dict[str, str]
    conda_name: str | None = None
    package_name: str | None = None
    direct_url: list[str] | None = None

    @property
    def pypi_purls(self) -> list[str]:
        return [
            normalize_purl(f"pkg:pypi/{name}") for name in self.pypi_normalized_names
        ]


def _clean_base_url(base_url: str | None = None) -> str:
    return (
        base_url or os.getenv("PARSELMOUTH_MAPPING_BASE_URL") or DEFAULT_BASE_URL
    ).rstrip("/")


def _parse_mapping(data: Any) -> ParselmouthMapping | None:
    if not isinstance(data, dict):
        return None

    names = data.get("pypi_normalized_names")
    if not isinstance(names, list):
        return None

    clean_names = sorted(
        {
            normalize_pypi_name(str(name).strip())
            for name in names
            if isinstance(name, str) and name.strip()
        }
    )
    if not clean_names:
        return None

    raw_versions = data.get("versions")
    versions = (
        {
            str(k): str(v)
            for k, v in raw_versions.items()
            if isinstance(k, str) and isinstance(v, str)
        }
        if isinstance(raw_versions, dict)
        else {}
    )

    raw_direct_url = data.get("direct_url")
    direct_url = (
        [str(u) for u in raw_direct_url if isinstance(u, str)]
        if isinstance(raw_direct_url, list)
        else None
    )

    return ParselmouthMapping(
        pypi_normalized_names=clean_names,
        versions=versions,
        conda_name=data.get("conda_name")
        if isinstance(data.get("conda_name"), str)
        else None,
        package_name=data.get("package_name")
        if isinstance(data.get("package_name"), str)
        else None,
        direct_url=direct_url,
    )


async def fetch_mapping_by_hash(
    client: httpx.AsyncClient,
    *,
    sha256: str | None,
    channel: str,
    base_url: str | None = None,
) -> ParselmouthMapping | None:
    """Fetch a public Parselmouth hash-v0 entry.

    Parselmouth stores hash entries at ``/hash-v0/{sha256}``; older docs also
    mention a channel-prefixed form, so we try that as a fallback.
    """
    if not sha256:
        return None

    base = _clean_base_url(base_url)
    paths = (
        f"/hash-v0/{sha256}",
        f"/{channel}/hash-v0/{sha256}",
    )

    for path in paths:
        try:
            resp = await client.get(f"{base}{path}", timeout=15.0)
        except httpx.HTTPError:
            continue
        if resp.status_code == 404:
            continue
        if resp.status_code != 200:
            continue
        try:
            return _parse_mapping(resp.json())
        except ValueError:
            return None
    return None
