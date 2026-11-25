# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Check shared action pins without copying a workflow's current release."""

from __future__ import annotations

import re
from collections.abc import Mapping

from yaml_loading import read_text

GRYPE_ACTION = "lfreleng-actions/grype-scan-action"
BUILD_ARTIFACT_ACTION = "lfreleng-actions/build-artifact-action"

FULL_SHA = re.compile(r"[0-9a-f]{40}")
VERSION_COMMENT = re.compile(r"  # v([0-9]+)\.([0-9]+)\.([0-9]+)")


def action_reference(action: str) -> re.Pattern[str]:
    """Match the action name, ref and comment, including in the raw text."""
    return re.compile(
        rf"(?<![\w/-]){re.escape(action)}(?:@(\S*)|(?=[ \t'\"#]|$))(.*)$",
        re.MULTILINE,
    )


def action_uses(action: str, source: str) -> str:
    """Read the first full uses value for the action from a workflow."""
    match = action_reference(action).search(source)
    return f"{action}@{match[1]}" if match and match[1] else ""


def check_pins(
    action: str,
    sources: Mapping[str, str],
    floor: tuple[int, int, int],
    counts: Mapping[str, int],
) -> None:
    """Require the expected calls to share one full SHA and version."""
    reference = action_reference(action)
    seen: set[tuple[str, str]] = set()
    sites: list[str] = []
    errors: list[str] = []
    for path, source in sources.items():
        matches = list(reference.finditer(source))
        if path in counts and len(matches) != counts[path]:
            errors.append(
                f"{path}: expected {counts[path]} calls, found {len(matches)}"
            )
        for match in matches:
            ref, comment = match[1] or "", match[2]
            line = source.count("\n", 0, match.start()) + 1
            site = f"{path}:{line}: {match[0]}"
            sites.append(site)
            seen.add((ref, comment))
            version = VERSION_COMMENT.fullmatch(comment)
            if not FULL_SHA.fullmatch(ref):
                errors.append(f"{path}:{line}: not a full commit SHA")
            elif version is None:
                errors.append(f"{path}:{line}: lacks its '  # vX.Y.Z' comment")
            elif tuple(map(int, version.groups())) < floor:
                minimum = ".".join(map(str, floor))
                errors.append(f"{path}:{line}: older than v{minimum}")
    if len(seen) != 1:
        errors.append("every call must share one pin")
    if errors:
        details = "\n".join([*errors, *sites])
        raise AssertionError(f"{action}:\n{details}")


def check_repinned(
    action: str,
    counts: Mapping[str, int],
    floor: tuple[int, int, int],
    pins: Mapping[str, str],
    *,
    count: int = 0,
) -> None:
    """Check workflow copies with the named files' refs/comments replaced.

    The replacement follows '@'. By default replace every call in each
    named file; pass count=1 to move only its first call.
    """
    sources = {path: read_text(path) for path in counts}
    reference = action_reference(action)
    for path, pin in pins.items():
        sources[path], replaced = reference.subn(
            f"{action}@{pin}", sources[path], count=count
        )
        if not replaced:
            raise AssertionError(f"{path} lost its {action} pin")
    check_pins(action, sources, floor, counts)
