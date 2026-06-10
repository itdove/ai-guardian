"""Tests for the web console sidebar search functionality."""

import pytest

pytest.importorskip("nicegui", reason="NiceGUI requires Python >= 3.10")


class TestNavGroups:
    """Verify NAV_GROUPS structure and content."""

    def test_nav_groups_has_eight_categories(self):
        from ai_guardian.web.components.header import NAV_GROUPS
        assert len(NAV_GROUPS) == 8

    def test_nav_groups_categories(self):
        from ai_guardian.web.components.header import NAV_GROUPS
        names = [g[0] for g in NAV_GROUPS]
        assert names == [
            "Security Overview",
            "Monitoring",
            "Permissions",
            "Secrets",
            "Prompt Injection",
            "Threat Detection",
            "Configuration",
            "Tools",
        ]

    def test_all_items_have_label_and_suffix(self):
        from ai_guardian.web.components.header import NAV_GROUPS
        for group_name, items in NAV_GROUPS:
            for entry in items:
                assert len(entry) == 2, f"Bad entry in {group_name}: {entry}"
                label, suffix = entry
                assert isinstance(label, str) and label
                assert isinstance(suffix, str)


class TestSearchIndex:
    """Verify _build_search_index produces correct entries."""

    def test_index_contains_nav_items(self):
        from ai_guardian.web.components.header import _build_search_index
        index = _build_search_index("/test")
        labels = [entry[1] for entry in index]
        assert "Security Dashboard" in labels
        assert "Global Settings" in labels
        assert "Permission Rules" in labels
        assert "Secret Scanning" in labels

    def test_index_contains_feature_toggles(self):
        from ai_guardian.web.components.header import _build_search_index
        index = _build_search_index("/test")
        labels = [entry[1] for entry in index]
        assert "PII Detection" in labels
        assert "Prompt Injection" in labels
        assert "Secret Redaction" in labels

    def test_feature_toggle_entries_point_to_settings(self):
        from ai_guardian.web.components.header import (
            NAV_GROUPS, _build_search_index,
        )
        index = _build_search_index("/test")
        nav_labels = set()
        for _, items in NAV_GROUPS:
            for label, _ in items:
                nav_labels.add(label)

        for search_text, label, group_name, path in index:
            if label not in nav_labels:
                assert path.startswith("/test/settings#feature-"), (
                    f"Feature toggle '{label}' should point to settings"
                )

    def test_search_text_is_lowercase(self):
        from ai_guardian.web.components.header import _build_search_index
        index = _build_search_index("/test")
        for search_text, _, _, _ in index:
            assert search_text == search_text.lower()

    def test_paths_use_prefix(self):
        from ai_guardian.web.components.header import _build_search_index
        index = _build_search_index("/myhost")
        for _, _, _, path in index:
            assert path.startswith("/myhost")

    def test_index_has_minimum_entries(self):
        from ai_guardian.web.components.header import _build_search_index
        index = _build_search_index("/test")
        assert len(index) >= 38, f"Expected >=38 entries, got {len(index)}"

    def test_feature_group_name_format(self):
        from ai_guardian.web.components.header import (
            NAV_GROUPS, _build_search_index,
        )
        index = _build_search_index("/test")
        nav_labels = set()
        for _, items in NAV_GROUPS:
            for label, _ in items:
                nav_labels.add(label)

        for _, label, group_name, _ in index:
            if label not in nav_labels:
                assert group_name.startswith("Settings ›")


class TestSearchMatching:
    """Verify substring search logic matches expected results."""

    def _match(self, query, index):
        q = query.strip().lower()
        return [
            (label, group_name, path)
            for search_text, label, group_name, path in index
            if q in search_text
        ]

    def test_ssrf_matches_nav_and_feature(self):
        from ai_guardian.web.components.header import _build_search_index
        index = _build_search_index("/d")
        results = self._match("ssrf", index)
        labels = [r[0] for r in results]
        assert "SSRF Protection" in labels
        assert len(results) >= 2

    def test_pii_matches_detection(self):
        from ai_guardian.web.components.header import _build_search_index
        index = _build_search_index("/d")
        results = self._match("pii", index)
        labels = [r[0] for r in results]
        assert "PII Detection" in labels

    def test_case_insensitive(self):
        from ai_guardian.web.components.header import _build_search_index
        index = _build_search_index("/d")
        lower = self._match("secret", index)
        upper = self._match("SECRET", index)
        assert len(lower) == len(upper)
        assert len(lower) >= 3

    def test_partial_match(self):
        from ai_guardian.web.components.header import _build_search_index
        index = _build_search_index("/d")
        results = self._match("perm", index)
        labels = [r[0] for r in results]
        assert "Permission Rules" in labels
        assert "Permissions Discovery" in labels

    def test_no_match(self):
        from ai_guardian.web.components.header import _build_search_index
        index = _build_search_index("/d")
        results = self._match("xyznonexistent", index)
        assert len(results) == 0

    def test_config_key_match(self):
        from ai_guardian.web.components.header import _build_search_index
        index = _build_search_index("/d")
        results = self._match("scan_pii", index)
        assert len(results) >= 1

    def test_description_keyword_match(self):
        from ai_guardian.web.components.header import _build_search_index
        index = _build_search_index("/d")
        results = self._match("ocr", index)
        labels = [r[0] for r in results]
        assert "Image Scanning" in labels

    def test_gdpr_matches_pii(self):
        from ai_guardian.web.components.header import _build_search_index
        index = _build_search_index("/d")
        results = self._match("gdpr", index)
        labels = [r[0] for r in results]
        assert "PII Detection" in labels


class TestNavGroupsConsistency:
    """Verify NAV_GROUPS matches original sidebar structure."""

    def test_total_nav_item_count(self):
        from ai_guardian.web.components.header import NAV_GROUPS
        total = sum(len(items) for _, items in NAV_GROUPS)
        assert total == 38

    def test_first_item_is_dashboard(self):
        from ai_guardian.web.components.header import NAV_GROUPS
        label, suffix = NAV_GROUPS[0][1][0]
        assert label == "Security Dashboard"
        assert suffix == ""

    def test_suffixes_start_with_slash_or_empty(self):
        from ai_guardian.web.components.header import NAV_GROUPS
        for group_name, items in NAV_GROUPS:
            for label, suffix in items:
                assert suffix == "" or suffix.startswith("/"), (
                    f"{group_name}/{label} has bad suffix: {suffix}"
                )
