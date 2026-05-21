from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from vaultsieve.models import Credential, Finding, normalize


@dataclass(frozen=True)
class DuplicateDecision:
    keep_id: str | None
    remove_ids: tuple[str, ...]
    reason: str


DuplicateKey = tuple[str, str, str, tuple[str, ...], str, str, str]


def duplicate_key(credential: Credential) -> DuplicateKey:
    return (
        normalize(credential.name),
        normalize(credential.username),
        credential.password,
        tuple(sorted(normalize(url) for url in credential.urls if normalize(url))),
        str(credential.has_passkey),
        str(credential.has_totp),
        str(credential.is_ssh_key),
    )


def analyze_duplicates(credentials: tuple[Credential, ...]) -> tuple[Finding, ...]:
    by_exact: dict[DuplicateKey, list[Credential]] = defaultdict(list)
    by_password: dict[str, list[Credential]] = defaultdict(list)

    for credential in credentials:
        by_exact[duplicate_key(credential)].append(credential)
        if credential.password:
            by_password[credential.password].append(credential)

    findings: list[Finding] = []
    for group in by_exact.values():
        if len(group) > 1:
            findings.append(
                Finding(
                    severity="high",
                    category="duplicate",
                    credential_ids=tuple(credential.id for credential in group),
                    explanation="These credentials are exact duplicates.",
                    recommendation="Keep one entry and remove the later duplicate entries after verifying them.",
                )
            )

    for group in by_password.values():
        unique_exact_keys = {duplicate_key(credential) for credential in group}
        if len(group) > 1 and len(unique_exact_keys) > 1:
            findings.append(
                Finding(
                    severity="high",
                    category="reuse",
                    credential_ids=tuple(credential.id for credential in group),
                    explanation="The same password is reused by multiple different entries.",
                    recommendation="Change these entries so each account has a unique password.",
                )
            )

    return tuple(findings)


def duplicate_removal_ids(credentials: tuple[Credential, ...]) -> set[str]:
    return {
        credential_id
        for decision in duplicate_cleanup_plan(credentials)
        for credential_id in decision.remove_ids
    }


def duplicate_groups(credentials: tuple[Credential, ...]) -> tuple[tuple[Credential, ...], ...]:
    grouped: dict[DuplicateKey, list[Credential]] = defaultdict(list)
    for credential in credentials:
        grouped[duplicate_key(credential)].append(credential)

    return tuple(tuple(group) for group in grouped.values() if len(group) > 1)


def duplicate_cleanup_plan(credentials: tuple[Credential, ...]) -> tuple[DuplicateDecision, ...]:
    decisions: list[DuplicateDecision] = []
    for group in duplicate_groups(credentials):
        scores = {credential.id: _keeper_score(credential) for credential in group}
        ranked = sorted(group, key=lambda credential: scores[credential.id], reverse=True)
        winner = ranked[0]
        if len(ranked) > 1 and scores[winner.id] == scores[ranked[1].id]:
            decisions.append(
                DuplicateDecision(
                    keep_id=None,
                    remove_ids=(),
                    reason="Ambiguous exact duplicate group; metadata score is tied.",
                )
            )
            continue
        decisions.append(
            DuplicateDecision(
                keep_id=winner.id,
                remove_ids=tuple(credential.id for credential in ranked[1:]),
                reason="Keeper has stronger metadata or newer update timestamp.",
            )
        )
    return tuple(decisions)


def _keeper_score(credential: Credential) -> tuple[int, int, int, int, int, int]:
    raw = credential.raw or {}
    return (
        _timestamp_score(raw),
        len(credential.urls),
        len(_non_empty_list(raw.get("uris"))) + len(_non_empty_list((raw.get("login") or {}).get("uris") if isinstance(raw.get("login"), dict) else None)),
        _metadata_richness(raw),
        int(bool(credential.name.strip())),
        int(bool(credential.username.strip())),
    )


def _timestamp_score(raw: dict[str, Any]) -> int:
    for key in ("revisionDate", "updated_at", "updatedAt", "modified", "last_modified"):
        value = raw.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        parsed = _parse_datetime(value)
        if parsed is not None:
            return int(parsed.timestamp())
    return 0


def _parse_datetime(value: str) -> datetime | None:
    normalized = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _metadata_richness(raw: dict[str, Any]) -> int:
    score = 0
    for key in ("notes", "folderId", "collectionIds", "fields", "favorite"):
        value = raw.get(key)
        if bool(value):
            score += 1
    return score


def _non_empty_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
