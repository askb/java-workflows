# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Pin agreement for the scanner and the m2repo hand-off."""

from __future__ import annotations

from action_pins import (
    BUILD_ARTIFACT_ACTION,
    GRYPE_ACTION,
    action_reference,
    check_pins,
    check_repinned,
)
from helpers import GRADLE, MAVEN, MERGE, TESTING, ContractCase
from yaml_loading import read_text

# The first verified release for the lanes' Grype gate and validation inputs.
GRYPE_FLOOR = (0, 6, 2)
# The first verified release for the m2repo ID and digest hand-off.
BUILD_ARTIFACT_FLOOR = (0, 1, 1)

GRYPE_COUNTS: dict[str, int] = dict.fromkeys(
    (MAVEN, GRADLE, MERGE, TESTING), 2
)
PIN_CONTRACTS = (
    (GRYPE_ACTION, GRYPE_COUNTS, GRYPE_FLOOR),
    (BUILD_ARTIFACT_ACTION, {MERGE: 2, TESTING: 1}, BUILD_ARTIFACT_FLOOR),
)

# Synthetic pins for the workflow-copy mutations, not release expectations.
NEW_SHA = "1" * 40
NEW_VERSION = "  # v99.0.0"


class SharedActionPins(ContractCase):
    """Every call pins a supported release, with no stale call sites."""

    def test_the_calls_share_a_supported_pin(self) -> None:
        """Check the real workflows, including the testing workflow."""
        for action, counts, floor in PIN_CONTRACTS:
            with self.subTest(action=action):
                sources = {path: read_text(path) for path in counts}
                check_pins(action, sources, floor, counts)

    def test_a_bump_of_every_call_passes(self) -> None:
        """A Dependabot bump needs no edits to the wiring checks."""
        for action, counts, floor in PIN_CONTRACTS:
            with self.subTest(action=action):
                pins = dict.fromkeys(counts, NEW_SHA + NEW_VERSION)
                check_repinned(action, counts, floor, pins)

    def test_one_call_at_another_pin_fails(self) -> None:
        """One stale call fails and the report locates both pins."""
        for action, counts, floor in PIN_CONTRACTS:
            with self.subTest(action=action):
                calls = list(
                    action_reference(action).finditer(read_text(MERGE))
                )
                current = calls[0][1]
                moved = ("2" if current == NEW_SHA else "1") * 40
                with self.assertRaisesRegex(
                    AssertionError, "every call must share one pin"
                ) as failure:
                    check_repinned(
                        action,
                        counts,
                        floor,
                        {MERGE: moved + calls[0][2]},
                        count=1,
                    )
                report = str(failure.exception)
                self.assertRegex(report, rf"{MERGE}:\d+: {action}@{moved}")
                self.assertRegex(report, rf"{MERGE}:\d+: {action}@{current}")
                self.assertRegex(report, rf"{TESTING}:\d+: {action}@{current}")

    def test_an_invalid_pin_fails(self) -> None:
        """Reject tags, branches, short SHAs and unlabelled or old pins."""
        mutants = (
            ("v99.0.0" + NEW_VERSION, "not a full commit SHA"),
            ("main" + NEW_VERSION, "not a full commit SHA"),
            ("1" * 7 + NEW_VERSION, "not a full commit SHA"),
            ("A" * 40 + NEW_VERSION, "not a full commit SHA"),
            (NEW_SHA, "lacks its"),
            (NEW_SHA + "  # v0.0.0", "older than"),
        )
        for action, counts, floor in PIN_CONTRACTS:
            for pin, error in mutants:
                with (
                    self.subTest(action=action, pin=pin),
                    self.assertRaisesRegex(AssertionError, error),
                ):
                    check_repinned(
                        action, counts, floor, dict.fromkeys(counts, pin)
                    )

    def test_one_grype_reference_fails(self) -> None:
        """A lane with the pin on the scan alone fails."""
        for path in (MAVEN, MERGE):
            with self.subTest(path=path):
                source = action_reference(GRYPE_ACTION).sub(
                    "", read_text(path), count=1
                )
                with self.assertRaisesRegex(
                    AssertionError, "expected 2 calls"
                ):
                    check_pins(
                        GRYPE_ACTION, {path: source}, GRYPE_FLOOR, GRYPE_COUNTS
                    )

    def test_a_third_grype_reference_fails(self) -> None:
        """A lane with a third Grype reference fails."""
        for path in (GRADLE, MERGE):
            with self.subTest(path=path):
                source = (
                    read_text(path) + f"\n# uses: {GRYPE_ACTION}@{NEW_SHA}\n"
                )
                with self.assertRaisesRegex(
                    AssertionError, "expected 2 calls"
                ):
                    check_pins(
                        GRYPE_ACTION, {path: source}, GRYPE_FLOOR, GRYPE_COUNTS
                    )
