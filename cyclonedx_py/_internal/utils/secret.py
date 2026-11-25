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

from re import Match, compile as re_compile

_URL_AUTH_MATCHER = re_compile(r'(?<=://)([^/\s?#"\'<>]+)@')
_URL_AUTH_REPLACE = ''  # drop auth - in accordance with PEP 610
_PEP610_SAFE_USERINFO = ('git',)
_PEP610_ENV_VAR_MATCHER = re_compile(r'^\$\{[A-Za-z0-9_-]+\}(?::\$\{[A-Za-z0-9_-]+\})?$')


def _redact_url_auth_match(match: Match[str]) -> str:
    userinfo = match.group(1)
    if userinfo in _PEP610_SAFE_USERINFO or _PEP610_ENV_VAR_MATCHER.match(userinfo):
        return match.group(0)
    return _URL_AUTH_REPLACE


def redact_auth_from_url(s: str) -> str:
    # is intended to work on any string that contains an url.
    return _URL_AUTH_MATCHER.sub(_redact_url_auth_match, s) \
        if '@' in s \
        else s
