# This file is part of CycloneDX Python
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.


from unittest import TestCase

from ddt import ddt, named_data

from cyclonedx_py._internal.utils.secret import redact_auth_from_url


@ddt
class TestUtilsSecret(TestCase):

    @named_data(
        ('no-at', 'https://pypi.org/simple/', 'https://pypi.org/simple/'),
        ('user-pass', 'https://user:password@pypi.company.com/simple/', 'https://pypi.company.com/simple/'),
        ('user-only-colon', 'https://user:@pypi.company.com/simple/', 'https://pypi.company.com/simple/'),
        ('pass-only-colon', 'https://:password@pypi.company.com/simple/', 'https://pypi.company.com/simple/'),
        ('single-token', 'https://0123456789abcdef@pypi.company.com/simple/', 'https://pypi.company.com/simple/'),
        (
            'single-token-git-vcs',
            'git+https://ghp_0123456789abcdef@github.com/benjaminp/six.git@1.16.0',
            'git+https://github.com/benjaminp/six.git@1.16.0',
        ),
        (
            'single-token-in-req-line',
            'requirements line 3: six @ git+https://ghp_0123456789abcdef@github.com/benjaminp/six.git@1.16.0',
            'requirements line 3: six @ git+https://github.com/benjaminp/six.git@1.16.0',
        ),
        (
            'user-with-at-and-pass',
            'https://user@example.com:password@pypi.company.com/simple/',
            'https://pypi.company.com/simple/',
        ),
        (
            'git-with-password',
            'https://git:secret_token@github.com/org/repo.git',
            'https://github.com/org/repo.git',
        ),
        (
            'pep610-git-ssh',
            'ssh://git@github.com/benjaminp/six.git',
            'ssh://git@github.com/benjaminp/six.git',
        ),
        (
            'pep610-git-plus-ssh',
            'git+ssh://git@github.com/benjaminp/six.git#egg=six',
            'git+ssh://git@github.com/benjaminp/six.git#egg=six',
        ),
        (
            'pep610-env-var-token',
            'https://${PYPI_TOKEN}@pypi.company.com/simple/',
            'https://${PYPI_TOKEN}@pypi.company.com/simple/',
        ),
        (
            'pep610-env-var-user-pass',
            'https://${PYPI_USER}:${PYPI_PASS}@pypi.company.com/simple/',
            'https://${PYPI_USER}:${PYPI_PASS}@pypi.company.com/simple/',
        ),
        (
            'partial-env-var-password-stripped',
            'https://${PYPI_USER}:literal_secret@pypi.company.com/simple/',
            'https://pypi.company.com/simple/',
        ),
        (
            'partial-env-var-user-stripped',
            'https://literal_user:${PYPI_PASS}@pypi.company.com/simple/',
            'https://pypi.company.com/simple/',
        ),
        (
            'non-userinfo-at-in-path',
            'https://github.com/org/repo.git@1.16.0',
            'https://github.com/org/repo.git@1.16.0',
        ),
        (
            'non-userinfo-at-in-query',
            'https://example.com?email=user@example.org',
            'https://example.com?email=user@example.org',
        ),
        (
            'non-userinfo-at-in-fragment',
            'https://example.com#section@1',
            'https://example.com#section@1',
        ),
        (
            'non-userinfo-at-after-space',
            'six @ https://example.com/six.whl user@example.org',
            'six @ https://example.com/six.whl user@example.org',
        ),
        (
            'multiple-urls-in-line',
            'pkg @ https://tok1@a.example.com/pkg.whl --extra-index-url https://tok2@b.example.com/simple/',
            'pkg @ https://a.example.com/pkg.whl --extra-index-url https://b.example.com/simple/',
        ),
    )
    def test_redact_auth_from_url(self, given: str, expected: str) -> None:
        self.assertEqual(expected, redact_auth_from_url(given))
