"""
Unit tests for skill_discovery module
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ai_guardian.skill_discovery import SkillDiscovery


class SkillDiscoveryTest(unittest.TestCase):
    """Test suite for SkillDiscovery"""

    def setUp(self):
        """Set up test fixtures"""
        # Create temporary cache directory
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.temp_dir) / "cache"
        self.discovery = SkillDiscovery(cache_dir=self.cache_dir)

    def tearDown(self):
        """Clean up test fixtures"""
        # Clean up temp directory
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_parse_github_url(self):
        """Test parsing GitHub directory URL"""
        url = "https://github.com/org/repo/tree/main/skills"
        result = self.discovery._parse_directory_url(url)

        self.assertIsNotNone(result)
        platform, hostname, owner, repo, branch, path = result

        self.assertEqual(platform, "github")
        self.assertEqual(hostname, "github.com")
        self.assertEqual(owner, "org")
        self.assertEqual(repo, "repo")
        self.assertEqual(branch, "main")
        self.assertEqual(path, "skills")

    def test_parse_gitlab_public_url(self):
        """Test parsing public GitLab.com directory URL"""
        url = "https://gitlab.com/org/repo/-/tree/main/skills"
        result = self.discovery._parse_directory_url(url)

        self.assertIsNotNone(result)
        platform, hostname, owner, repo, branch, path = result

        self.assertEqual(platform, "gitlab")
        self.assertEqual(hostname, "gitlab.com")
        self.assertEqual(owner, "org")
        self.assertEqual(repo, "repo")
        self.assertEqual(branch, "main")
        self.assertEqual(path, "skills")

    def test_parse_gitlab_selfhosted_url(self):
        """Test parsing self-hosted GitLab directory URL"""
        url = "https://gitlab.example.com/org/repo/-/tree/main/skills"
        result = self.discovery._parse_directory_url(url)

        self.assertIsNotNone(result)
        platform, hostname, owner, repo, branch, path = result

        self.assertEqual(platform, "gitlab")
        self.assertEqual(hostname, "gitlab.example.com")
        self.assertEqual(owner, "org")
        self.assertEqual(repo, "repo")
        self.assertEqual(branch, "main")
        self.assertEqual(path, "skills")

    def test_parse_gitlab_multilevel_group_url(self):
        """Test parsing GitLab URL with multi-level groups"""
        url = "https://gitlab.example.com/group/subgroup/repo/-/tree/develop/path/to/skills"
        result = self.discovery._parse_directory_url(url)

        self.assertIsNotNone(result)
        platform, hostname, owner, repo, branch, path = result

        self.assertEqual(platform, "gitlab")
        self.assertEqual(hostname, "gitlab.example.com")
        self.assertEqual(owner, "group/subgroup")
        self.assertEqual(repo, "repo")
        self.assertEqual(branch, "develop")
        self.assertEqual(path, "path/to/skills")

    def test_discover_gitlab_public_skills(self):
        """Test discovering skills from public GitLab.com"""
        url = "https://gitlab.com/org/repo/-/tree/main/skills"

        # Mock GitLab API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name": "arc", "type": "tree"},
            {"name": "code-review", "type": "tree"},
            {"name": ".hidden", "type": "tree"},  # Should be skipped
            {"name": "README.md", "type": "blob"},  # Should be skipped
        ]

        with patch('requests.get', return_value=mock_response) as mock_get:
            skills = self.discovery.discover_skills(url, cache_ttl_hours=0)

            # Verify API was called with correct URL
            self.assertTrue(mock_get.called)
            call_args = mock_get.call_args
            api_url = call_args[0][0]

            # Should use gitlab.com, not hardcoded
            self.assertIn("https://gitlab.com/api/v4", api_url)
            self.assertIn("org%2Frepo", api_url)

            # Verify skills were discovered
            self.assertEqual(skills, {"Skill:arc", "Skill:code-review"})

    def test_discover_gitlab_selfhosted_skills(self):
        """Test discovering skills from self-hosted GitLab instance"""
        url = "https://gitlab.example.com/org/repo/-/tree/main/skills"

        # Mock GitLab API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name": "daf-active", "type": "tree"},
            {"name": "daf-config", "type": "tree"},
        ]

        with patch('requests.get', return_value=mock_response) as mock_get:
            skills = self.discovery.discover_skills(url, cache_ttl_hours=0)

            # Verify API was called with self-hosted hostname
            self.assertTrue(mock_get.called)
            call_args = mock_get.call_args
            api_url = call_args[0][0]

            # CRITICAL: Should use gitlab.example.com, NOT gitlab.com
            self.assertIn("https://gitlab.example.com/api/v4", api_url)
            self.assertNotIn("gitlab.com/api/v4", api_url)

            # Verify skills were discovered
            self.assertEqual(skills, {"Skill:daf-active", "Skill:daf-config"})

    def test_discover_github_skills(self):
        """Test discovering skills from GitHub"""
        url = "https://github.com/org/repo/tree/main/skills"

        # Mock GitHub API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name": "release", "type": "dir"},
            {"name": "init", "type": "dir"},
            {"name": "__pycache__", "type": "dir"},  # Should be skipped
            {"name": "README.md", "type": "file"},  # Should be skipped
        ]

        with patch('requests.get', return_value=mock_response) as mock_get:
            skills = self.discovery.discover_skills(url, cache_ttl_hours=0)

            # Verify API was called with correct URL
            self.assertTrue(mock_get.called)
            call_args = mock_get.call_args
            api_url = call_args[0][0]

            # Should use GitHub API
            self.assertIn("https://api.github.com/repos/org/repo/contents", api_url)

            # Verify skills were discovered
            self.assertEqual(skills, {"Skill:release", "Skill:init"})

    def test_gitlab_authentication_token(self):
        """Test GitLab authentication with custom token"""
        url = "https://gitlab.example.com/org/repo/-/tree/main/skills"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"name": "test-skill", "type": "tree"}]

        with patch('requests.get', return_value=mock_response) as mock_get:
            with patch('os.environ.get', return_value="custom-token"):
                skills = self.discovery.discover_skills(
                    url,
                    cache_ttl_hours=0,
                    token_env="CUSTOM_GITLAB_TOKEN"
                )

                # Verify authentication header was set
                self.assertTrue(mock_get.called)
                call_kwargs = mock_get.call_args[1]
                headers = call_kwargs.get('headers', {})

                self.assertIn('PRIVATE-TOKEN', headers)
                self.assertEqual(headers['PRIVATE-TOKEN'], 'custom-token')

    def test_gitlab_404_error(self):
        """Test handling of 404 error from GitLab API"""
        url = "https://gitlab.example.com/org/repo/-/tree/main/nonexistent"

        mock_response = Mock()
        mock_response.status_code = 404

        with patch('requests.get', return_value=mock_response):
            skills = self.discovery.discover_skills(url, cache_ttl_hours=0)

            # Should return empty set on 404
            self.assertEqual(skills, set())

    def test_gitlab_401_unauthorized(self):
        """Test handling of 401 authentication error"""
        url = "https://gitlab.example.com/org/private-repo/-/tree/main/skills"

        mock_response = Mock()
        mock_response.status_code = 401

        with patch('requests.get', return_value=mock_response):
            skills = self.discovery.discover_skills(url, cache_ttl_hours=0)

            # Should return empty set on 401
            self.assertEqual(skills, set())

    def test_local_directory_discovery(self):
        """Test discovering skills from local filesystem"""
        # Create temporary skill directories
        skills_dir = Path(self.temp_dir) / "local-skills"
        skills_dir.mkdir()

        (skills_dir / "skill-a").mkdir()
        (skills_dir / "skill-b").mkdir()
        (skills_dir / ".hidden").mkdir()  # Should be skipped
        (skills_dir / "__pycache__").mkdir()  # Should be skipped

        # Discover from local path
        skills = self.discovery.discover_skills(str(skills_dir))

        # Verify skills were discovered
        self.assertEqual(skills, {"Skill:skill-a", "Skill:skill-b"})

    def test_cache_functionality(self):
        """Test that skill discovery results are cached"""
        url = "https://gitlab.example.com/org/repo/-/tree/main/skills"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name": "cached-skill", "type": "tree"}
        ]

        with patch('requests.get', return_value=mock_response) as mock_get:
            # First call - should hit API
            skills1 = self.discovery.discover_skills(url, cache_ttl_hours=24)
            first_call_count = mock_get.call_count

            # Second call - should use cache
            skills2 = self.discovery.discover_skills(url, cache_ttl_hours=24)
            second_call_count = mock_get.call_count

            # Verify cache was used (no additional API call)
            self.assertEqual(first_call_count, second_call_count)
            self.assertEqual(skills1, skills2)
            self.assertEqual(skills1, {"Skill:cached-skill"})

    def test_invalid_url_format(self):
        """Test handling of invalid URL formats"""
        invalid_urls = [
            "https://example.com/not-a-repo",
            "https://github.com/org",  # Missing parts
            "https://gitlab.com/org/repo/tree/main",  # Missing -/ for GitLab
            "not-a-url-at-all",
        ]

        for invalid_url in invalid_urls:
            result = self.discovery._parse_directory_url(invalid_url)
            # Most should return None (invalid format)
            # The last one is not http/https so it will be treated as local path
            if invalid_url.startswith("http"):
                self.assertIsNone(result, f"Expected None for {invalid_url}")


if __name__ == '__main__':
    unittest.main()
