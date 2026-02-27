#!/usr/bin/env python3

import re
import json
import base64
import logging
import requests
from requests.exceptions import HTTPError
import subprocess
import time
from urllib.parse import quote

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as ec
from webdriver_manager.chrome import ChromeDriverManager

CHROME_OPTIONS = webdriver.ChromeOptions()
CHROME_OPTIONS.add_argument("--headless")
CHROME_OPTIONS.add_argument("--no-sandbox")
CHROME_OPTIONS.add_argument("--disable-dev-shm-usage")

_LOGGER = logging.getLogger(__name__)
HOST = "churchofjesuschrist.org"
BETA_HOST = f"beta.{HOST}"
LCR_DOMAIN = f"lcr.{HOST}"
FFE_DOMAIN = f"lcrffe.{HOST}"
TIMEOUT = 10
CHROME_BINARIES = (
    "google-chrome",
    "google-chrome-stable",
    "google-chrome-beta",
    "google-chrome-dev",
    "chromium",
    "chromium-browser",
)

if _LOGGER.getEffectiveLevel() <= logging.DEBUG:
    import http.client as http_client
    http_client.HTTPConnection.debuglevel = 1


class InvalidCredentialsError(Exception):
    pass


class EndpointUnavailableError(Exception):
    pass


def _detect_local_chrome_major_version():
    for chrome_binary in CHROME_BINARIES:
        try:
            version_output = subprocess.check_output(
                [chrome_binary, "--version"],
                stderr=subprocess.STDOUT,
                text=True,
            ).strip()
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue

        match = re.search(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", version_output)
        if match:
            return match.group(1)

    return None


def _build_chromedriver_service():
    detected_major = _detect_local_chrome_major_version()
    if detected_major:
        _LOGGER.info("Detected local Chrome/Chromium major version %s", detected_major)
        manager = ChromeDriverManager(driver_version=detected_major)
    else:
        _LOGGER.warning("Could not detect local Chrome/Chromium version. Falling back to latest chromedriver.")
        manager = ChromeDriverManager()

    return Service(manager.install())


class API:
    def __init__(self, username, password, unit_number, beta=False):
        # create Chrome only when API is instantiated
        service = _build_chromedriver_service()
        self.driver = webdriver.Chrome(service=service, options=CHROME_OPTIONS)

        self.unit_number = unit_number
        self.session = requests.Session()
        self.beta = beta
        self.host = BETA_HOST if beta else HOST
        self.regular_cookies = {}
        self.ffe_cookies = {}

        self._login(username, password)

    def load_cookies(self, use_ffe=False):
        cookies_to_load = self.ffe_cookies if use_ffe else self.regular_cookies
        self.session.cookies.clear()
        for cookie_name, cookie_value in cookies_to_load.items():
            self.session.cookies.set(cookie_name, cookie_value)

    def get_ffe_cookies(self):

        if self.driver is None:
            service = _build_chromedriver_service()
            self.driver = webdriver.Chrome(service=service, options=CHROME_OPTIONS)

        self.driver.get(f"https://{FFE_DOMAIN}")

        # Wait until the page is loaded
        WebDriverWait(self.driver, TIMEOUT).until(
                ec.presence_of_element_located(
                    (By.CSS_SELECTOR, "platform-header.PFshowHeader")
                    )
                )

        time.sleep(5) # Unable to find a better item above to wait on, but the above still needs some of the page to load.

        _LOGGER.info("getting ffe cookies")

        # Capture FFE cookies separately from regular LCR cookies.
        cookies = self.driver.get_cookies()
        self.ffe_cookies = {
            cookie['name']: cookie['value']
            for cookie in cookies
        }


    def _login(self, user, password):
        _LOGGER.info("Logging in")

        # Navigate to the login page
        self.driver.get(f"https://{LCR_DOMAIN}")

        _LOGGER.info("Entering username")

        # Enter the username
        login_input = WebDriverWait(self.driver, TIMEOUT).until(
                        ec.presence_of_element_located(
                            (By.XPATH, "//input[@autocomplete='username']") # Have to use another field, they keep changing the ID
                            )
                        )
        login_input.send_keys(user)

        # Find the "Next" button and click it
        next_button = self.driver.find_element(By.ID, "button-primary")
        next_button.click()

        _LOGGER.info("Entering password")

         # Enter password
        password_input = WebDriverWait(self.driver, TIMEOUT).until(
                ec.presence_of_element_located(
                        (By.CSS_SELECTOR, "input#password-input")  # or input.eden-form-part-input__control
                    )
                )
        password_input.send_keys(password)

        # Find the "Verify" button and click it
        verify_password_button = self.driver.find_element(By.ID, "button-primary")
        verify_password_button.click()

        # Wait until the page is loaded
        WebDriverWait(self.driver, TIMEOUT).until(
                ec.presence_of_element_located(
                    (By.CSS_SELECTOR, "platform-header.PFshowHeader")
                    )
                )

        time.sleep(5) # Unable to find a better item above to wait on, but the above still needs some of the page to load.

        # Warm an MLT page so mltpSession and related cookies are available
        # for React Server Component action endpoints (for example, moved-in).
        self.driver.get(f"https://{LCR_DOMAIN}/mlt/report/members-moved-in?lang=eng")
        time.sleep(5)

        _LOGGER.info("Successfully logged in, getting cookies")

        # Capture regular LCR cookies.
        cookies = self.driver.get_cookies()
        self.regular_cookies = {
            cookie['name']: cookie['value']
            for cookie in cookies
        }

        self.get_ffe_cookies()

        # Default to regular (non-FFE) cookies for all requests.
        self.load_cookies(use_ffe=False)

        self.driver.close()
        self.driver.quit()

    def _make_get_request(self, request, use_ffe=False):
        self.load_cookies(use_ffe=use_ffe)

        if self.beta:
            request['cookies'] = {'clerk-resources-beta-terms': '4.1',
                                  'clerk-resources-beta-eula': '4.2'}

        response = self.session.get(**request)
        response.raise_for_status()  # break on any non 200 status
        return response

    def _make_post_request(self, request, use_ffe=False):
        self.load_cookies(use_ffe=use_ffe)

        if self.beta:
            request['cookies'] = {'clerk-resources-beta-terms': '4.1',
                                  'clerk-resources-beta-eula': '4.2'}

        response = self.session.post(**request)
        response.raise_for_status()
        return response

    def _make_get_request_with_domain_fallback(self, request_factory):
        last_error = None
        for domain, use_ffe in ((LCR_DOMAIN, False), (FFE_DOMAIN, True)):
            request = request_factory(domain)
            try:
                return self._make_get_request(request, use_ffe=use_ffe)
            except requests.exceptions.HTTPError as exc:
                status_code = exc.response.status_code if exc.response is not None else None
                if status_code == 404:
                    _LOGGER.info("Endpoint not found on %s; trying next domain", domain)
                    last_error = exc
                    continue
                raise

        if last_error is not None:
            raise last_error

        raise RuntimeError("No domain candidates available for GET request")

    def _make_post_request_with_domain_fallback(self, request_factory):
        last_error = None
        for domain, use_ffe in ((LCR_DOMAIN, False), (FFE_DOMAIN, True)):
            request = request_factory(domain)
            try:
                return self._make_post_request(request, use_ffe=use_ffe)
            except requests.exceptions.HTTPError as exc:
                status_code = exc.response.status_code if exc.response is not None else None
                if status_code == 404:
                    _LOGGER.info("Endpoint not found on %s; trying next domain", domain)
                    last_error = exc
                    continue
                raise

        if last_error is not None:
            raise last_error

        raise RuntimeError("No domain candidates available for POST request")

    def _parse_json_response(self, response, endpoint_name):
        try:
            return response.json()
        except ValueError as exc:
            content_type = response.headers.get('content-type', '')
            message = (
                f"{endpoint_name} did not return JSON "
                f"(status={response.status_code}, content-type={content_type}, url={response.url})"
            )
            raise EndpointUnavailableError(message) from exc

    def _parse_rsc_array_response(self, response, endpoint_name):
        if not hasattr(response, 'text') and hasattr(response, 'json'):
            try:
                parsed = response.json()
            except ValueError:
                parsed = None
            if parsed is not None:
                return parsed

        body = response.text or ""
        parsed_arrays = []
        for raw_line in body.splitlines():
            line = raw_line.strip()
            if not line or ':' not in line:
                continue
            _, payload = line.split(':', 1)
            payload = payload.strip()
            if not payload.startswith('['):
                continue
            try:
                parsed = json.loads(payload)
            except ValueError:
                continue
            if isinstance(parsed, list):
                parsed_arrays.append(parsed)

        if parsed_arrays:
            for candidate in parsed_arrays:
                if candidate and isinstance(candidate[0], dict):
                    return candidate
            return parsed_arrays[0]

        message = (
            f"{endpoint_name} did not return a parseable RSC array "
            f"(status={response.status_code}, content-type={response.headers.get('content-type', '')}, url={response.url})"
        )
        raise EndpointUnavailableError(message)

    def _extract_first_list_from_rsc(self, response_text):
        if not response_text:
            return []

        def _first_list(value):
            if isinstance(value, list):
                if value:
                    return value
                return None
            if isinstance(value, dict):
                for nested in value.values():
                    found = _first_list(nested)
                    if found is not None:
                        return found
            return None

        for raw_line in response_text.splitlines():
            line = raw_line.strip()
            if not line or ':' not in line:
                continue

            _, payload = line.split(':', 1)
            payload = payload.strip()
            if not payload:
                continue

            if not (payload.startswith('{') or payload.startswith('[')):
                continue

            try:
                parsed = json.loads(payload)
            except ValueError:
                continue

            found = _first_list(parsed)
            if found is not None:
                return found

        return []

    def _build_mlt_identity_payload(self):
        identity = {}
        owp_token = self.regular_cookies.get('owp')
        if owp_token:
            try:
                token_parts = owp_token.split('.')
                if len(token_parts) >= 2:
                    payload_part = token_parts[1]
                    payload_part += '=' * (-len(payload_part) % 4)
                    decoded = base64.urlsafe_b64decode(payload_part.encode('utf-8')).decode('utf-8')
                    claims = json.loads(decoded)
                    if isinstance(claims, dict):
                        keep_keys = [
                            'sub', 'name', 'email', 'ver', 'jti', 'amr', 'idp', 'preferred_username',
                            'churchCMISID', 'lastName', 'firstName', 'churchCMISUUID',
                            'churchAccountID', 'displayName', 'personalEmail',
                        ]
                        identity = {key: claims[key] for key in keep_keys if key in claims}
            except (ValueError, json.JSONDecodeError, base64.binascii.Error):
                identity = {}

        if identity:
            return identity

        try:
            sign_in = self._make_get_request({
                'url': f'https://www.{HOST}/services/platform/v4/sign-in',
                'params': {'lang': 'eng', 'referer': '', 'format': 'json'},
            }, use_ffe=False)
            parsed = self._parse_json_response(sign_in, 'sign_in')
            return {
                'sub': parsed.get('userId'),
                'name': parsed.get('linkname'),
                'churchAccountID': parsed.get('account'),
                'displayName': parsed.get('linkname'),
            }
        except (HTTPError, EndpointUnavailableError, requests.RequestException):
            return {}

    def _discover_next_actions_for_route(self, route_path):
        if not hasattr(self, 'session'):
            return []

        try:
            page = self.session.get(
                f'https://{LCR_DOMAIN}{route_path}',
                params={'lang': 'eng'},
                timeout=TIMEOUT,
            )
            page.raise_for_status()
        except requests.RequestException:
            return []

        script_paths = re.findall(r'<script[^>]+src="([^"]+)"', page.text or '')
        action_ids = []
        seen = set()
        for script_path in script_paths:
            if not script_path.startswith('/mlt/_next/static/chunks/'):
                continue
            script_url = f'https://{LCR_DOMAIN}{script_path}'
            try:
                script_text = self.session.get(script_url, timeout=TIMEOUT).text
            except requests.RequestException:
                continue
            discovered = re.findall(
                r'createServerReference\("([a-f0-9]{32,128})"',
                script_text,
                re.IGNORECASE,
            )
            if not discovered:
                discovered = re.findall(r'\b[a-f0-9]{40,128}\b', script_text, re.IGNORECASE)

            for action_id in discovered:
                normalized_action_id = action_id.lower()
                if normalized_action_id not in seen:
                    seen.add(normalized_action_id)
                    action_ids.append(normalized_action_id)

        return action_ids

    def _normalize_members_moved_in_row(self, row):
        if not isinstance(row, dict):
            return row

        normalized = dict(row)
        text_address_parts = [
            str(row.get('addressFormatted1', '')).strip(),
            str(row.get('addressFormatted2', '')).strip(),
            str(row.get('addressFormatted3', '')).strip(),
        ]
        text_address = ', '.join(part for part in text_address_parts if part)

        alias_values = {
            'gender': row.get('sex'),
            'nameOrder': row.get('name'),
            'genderLabelShort': row.get('sex'),
            'priesthood': row.get('priesthood'),
            'addressUnknown': row.get('cameFromAddressUnknown'),
            'birthdate': row.get('birthdate'),
            'birthdateCalc': row.get('birthdateCalc'),
            'moveDate': row.get('unitMoveInDate'),
            'moveDateCalc': row.get('unitMoveInDateDisplay'),
            'unitName': row.get('membershipUnitName'),
            'address': row.get('addressFormatted1'),
            'id': row.get('uuid'),
            'householdPositionEnum': row.get('householdPosition'),
            'moveDateOrder': row.get('unitMoveInDate'),
            'textAddress': text_address,
            'locale': row.get('locale', 'eng'),
            'householdUuid': row.get('uuid'),
        }

        for key, value in alias_values.items():
            if key not in normalized or normalized.get(key) is None:
                normalized[key] = value

        return normalized

    def _build_report_router_state_tree(self, report_slug):
        return quote(
            json.dumps(
                [
                    "",
                    {
                        "children": [
                            "report",
                            {
                                "children": [
                                    report_slug,
                                    {"children": ["__PAGE__", {}, None, None]},
                                    None,
                                    None,
                                ]
                            },
                            None,
                            None,
                        ]
                    },
                    None,
                    None,
                    True,
                ],
                separators=(',', ':'),
            ),
            safe='',
        )

    def _extract_birthday_initial_data(self, response_text):
        if not response_text:
            return []

        match = re.search(r'"initialData":(\[.*?\]),"unitNumber"', response_text, re.DOTALL)
        if not match:
            return []

        try:
            parsed = json.loads(match.group(1))
        except ValueError:
            return []

        return parsed if isinstance(parsed, list) else []

    def _month_in_range(self, birth_month, start_month, month_count):
        if month_count <= 0:
            return False
        month_window = {((start_month - 1 + offset) % 12) + 1 for offset in range(month_count)}
        return birth_month in month_window

    def _normalize_birthday_row(self, row):
        if not isinstance(row, dict):
            return row

        birth_date_raw = str(row.get('birthDate', ''))
        birth_month = None
        birth_day = None
        if '-' in birth_date_raw:
            try:
                birth_month = int(birth_date_raw.split('-', 1)[0])
                birth_day = int(birth_date_raw.split('-', 1)[1])
            except ValueError:
                birth_month = None
                birth_day = None

        formatted_address = str(row.get('addressDisplay') or '').replace('<br />', ', ').strip(', ')
        birthday_display = row.get('birthDateDisplay') or row.get('birthDate')

        return {
            'name': row.get('name'),
            'spokenName': row.get('name'),
            'nameOrder': row.get('name'),
            'birthDate': birthday_display,
            'birthDateSort': row.get('birthDate'),
            'birthDaySort': birth_day,
            'birthDayFormatted': birthday_display,
            'birthDateFormatted': birthday_display,
            'gender': row.get('gender'),
            'genderCode': row.get('genderCode'),
            'mrn': row.get('mrn'),
            'id': row.get('personUuid'),
            'email': row.get('email'),
            'householdEmail': row.get('householdEmail'),
            'phone': row.get('phone'),
            'householdPhone': row.get('householdPhone'),
            'unitNumber': row.get('currentUnitId'),
            'unitName': row.get('currentUnitName'),
            'priesthood': row.get('priesthood'),
            'priesthoodCode': row.get('priesthoodCode'),
            'priesthoodType': row.get('priesthoodType'),
            'age': row.get('age'),
            'actualAge': row.get('age'),
            'actualAgeInMonths': row.get('actualAgeInMonths'),
            'genderLabelShort': row.get('genderLabelShort') or row.get('gender'),
            'visible': True,
            'nonMember': False,
            'outOfUnitMember': False,
            'notAccountable': False,
            'address': formatted_address,
            'monthInteger': birth_month,
            'dayInteger': birth_day,
            'birthDayAge': row.get('age'),
            'displayBirthdate': birthday_display,
            'sustainedDate': row.get('sustainedDate'),
            'formattedMrn': row.get('formattedMrn'),
            'setApart': row.get('setApart'),
            'accountable': True,
        }

    def _normalize_members_moved_out_row(self, row):
        if not isinstance(row, dict):
            return row

        new_unit_name = row.get('newUnitName') or row.get('newUnitDisplay')
        membership_status = str(row.get('membershipStatus') or '').upper()

        return {
            'deceased': membership_status == 'DECEASED' or str(row.get('newUnitDisplay') or '').lower() == 'deceased',
            'nextUnitNumber': row.get('newUnitNumber'),
            'name': row.get('name'),
            'nextUnitName': new_unit_name,
            'addressUnknown': row.get('addressUnknown', False),
            'moveDate': row.get('movedOutDateDisplay') or row.get('movedOutDate'),
            'priorUnit': row.get('priorUnit') or self.unit_number,
            'moveDateOrder': row.get('movedOutDate'),
            'birthDate': row.get('birthDateDisplay') or row.get('birthDate'),
            'nameOrder': row.get('name'),
        }

    def birthday_list(self, month, months=1):
        _LOGGER.info("Getting birthday list")
        route_slug = 'birthday-list'
        route_path = f'/mlt/report/{route_slug}'
        router_state_tree = self._build_report_router_state_tree(route_slug)
        request = {
            'url': f'https://{LCR_DOMAIN}{route_path}',
            'params': {
                'lang': 'eng',
                '_rsc': hex(int(time.time() * 1000000))[2:],
            },
            'headers': {
                'Accept': '*/*',
                'rsc': '1',
                'Referer': f'https://{LCR_DOMAIN}/',
                'next-router-state-tree': router_state_tree,
                'next-url': '/report/members-moved-out',
            },
        }
        result = self._make_get_request(request, use_ffe=False)

        rows = self._extract_birthday_initial_data(result.text or '')
        if not rows:
            raise EndpointUnavailableError('birthday_list did not return initialData rows')

        filtered_rows = []
        for row in rows:
            birth_date_raw = str(row.get('birthDate', ''))
            if '-' not in birth_date_raw:
                continue
            try:
                birth_month = int(birth_date_raw.split('-', 1)[0])
            except ValueError:
                continue
            if self._month_in_range(birth_month, int(month), int(months)):
                filtered_rows.append(self._normalize_birthday_row(row))

        return [{'birthdays': filtered_rows}]

    def members_moved_in(self, months):
        _LOGGER.info("Getting members moved in")
        route_path = '/mlt/report/members-moved-in'
        router_state_tree = quote(
            json.dumps(
                [
                    "",
                    {
                        "children": [
                            "report",
                            {
                                "children": [
                                    "members-moved-in",
                                    {"children": ["__PAGE__", {}, None, None]},
                                    None,
                                    None,
                                ]
                            },
                            None,
                            None,
                        ]
                    },
                    None,
                    None,
                    True,
                ],
                separators=(',', ':'),
            ),
            safe='',
        )

        payload = json.dumps([int(self.unit_number), int(months)], separators=(',', ':'))
        base_headers = {
            'Accept': 'text/x-component',
            'Content-Type': 'text/plain;charset=UTF-8',
            'Origin': f'https://{LCR_DOMAIN}',
            'Referer': f'https://{LCR_DOMAIN}{route_path}?lang=eng',
            'next-router-state-tree': router_state_tree,
        }

        action_ids = self._discover_next_actions_for_route(route_path)
        if not action_ids:
            action_ids = [None]

        last_error = None
        for action_id in action_ids:
            headers = dict(base_headers)
            if action_id:
                headers['next-action'] = action_id

            request = {
                'url': 'https://{}{}'.format(LCR_DOMAIN, route_path),
                'params': {'lang': 'eng'},
                'headers': headers,
                'data': payload,
            }

            try:
                result = self._make_post_request(request, use_ffe=False)
                parsed = self._parse_rsc_array_response(result, 'members_moved_in')
                if isinstance(parsed, list):
                    return [self._normalize_members_moved_in_row(item) for item in parsed]
                return parsed
            except HTTPError as exc:
                status_code = exc.response.status_code if exc.response is not None else None
                if status_code == 404:
                    last_error = exc
                    continue
                raise
            except EndpointUnavailableError as exc:
                last_error = exc
                continue

        if last_error is not None:
            raise last_error

        raise EndpointUnavailableError('members_moved_in did not return data')


    def members_moved_out(self, months):
        _LOGGER.info("Getting members moved out")
        route_slug = 'members-moved-out'
        route_path = f'/mlt/report/{route_slug}'
        router_state_tree = self._build_report_router_state_tree(route_slug)

        payload = json.dumps([int(self.unit_number), int(months)], separators=(',', ':'))
        base_headers = {
            'Accept': 'text/x-component',
            'Content-Type': 'text/plain;charset=UTF-8',
            'Origin': f'https://{LCR_DOMAIN}',
            'Referer': f'https://{LCR_DOMAIN}/',
            'next-router-state-tree': router_state_tree,
        }

        action_ids = self._discover_next_actions_for_route(route_path)
        if not action_ids:
            action_ids = [None]

        last_error = None
        for action_id in action_ids:
            headers = dict(base_headers)
            if action_id:
                headers['next-action'] = action_id

            request = {
                'url': f'https://{LCR_DOMAIN}{route_path}',
                'params': {'lang': 'eng'},
                'headers': headers,
                'data': payload,
            }

            try:
                result = self._make_post_request(request, use_ffe=False)
                parsed = self._parse_rsc_array_response(result, 'members_moved_out')
                if isinstance(parsed, list):
                    return [self._normalize_members_moved_out_row(item) for item in parsed]
                return parsed
            except HTTPError as exc:
                status_code = exc.response.status_code if exc.response is not None else None
                if status_code == 404:
                    last_error = exc
                    continue
                raise
            except EndpointUnavailableError as exc:
                last_error = exc
                continue

        if last_error is not None:
            raise last_error

        raise EndpointUnavailableError('members_moved_out did not return data')


    def member_list(self):
        _LOGGER.info("Getting member list")
        request = {
            'url': 'https://{}/api/umlu/report/member-list'.format(LCR_DOMAIN),
            'params': {
                'lang': 'eng',
                'unitNumber': self.unit_number
            }
        }

        result = self._make_get_request(request)
        return result.json()


    def member_profile(self, member_id):
        _LOGGER.info("Getting member profile")
        result = self._make_get_request_with_domain_fallback(
            lambda domain: {
                'url': 'https://{}/api/records/member-profile/service/{}'.format(domain, member_id),
                'params': {'lang': 'eng'},
            }
        )
        return self._parse_json_response(result, 'member_profile')


    def individual_photo(self, member_id):
        """
        member_id is not the same as Mrn
        """
        _LOGGER.info("Getting photo for {}".format(member_id))
        request = {
            'url': 'https://{}/api/avatar/{}/MEDIUM'.format(LCR_DOMAIN, member_id),
            'params': {
                'lang': 'eng',
                'status': 'APPROVED'
            }
        }

        result = self._make_get_request(request)
        scdn_url = result.json()['tokenUrl']
        return self._make_get_request({'url': scdn_url}).content


    def callings(self):
        _LOGGER.info("Getting callings for all organizations")
        route_slug = 'member-callings'
        route_path = f'/mlt/report/{route_slug}'
        router_state_tree = self._build_report_router_state_tree(route_slug)

        identity_payload = self._build_mlt_identity_payload()
        payload = json.dumps(
            [
                identity_payload,
                'eng',
                {
                    'bundles': ['callings', 'record'],
                    'extraKeys': ['cdol-lcr.email', 'patriarchal-blessings.select.unit.dropdown'],
                },
            ],
            separators=(',', ':'),
        )

        base_headers = {
            'Accept': 'text/x-component',
            'Content-Type': 'text/plain;charset=UTF-8',
            'Origin': f'https://{LCR_DOMAIN}',
            'Referer': f'https://{LCR_DOMAIN}/',
            'next-router-state-tree': router_state_tree,
        }

        action_ids = self._discover_next_actions_for_route(route_path)
        if not action_ids:
            action_ids = ['7fc068a010d14bbfcb1e959a677fc0dec1dac50d97']

        last_error = None
        for action_id in action_ids:
            headers = dict(base_headers)
            headers['next-action'] = action_id

            request = {
                'url': f'https://{LCR_DOMAIN}{route_path}',
                'params': {'lang': 'eng'},
                'headers': headers,
                'data': payload,
            }

            try:
                result = self._make_post_request(request, use_ffe=False)
                parsed = self._extract_first_list_from_rsc(result.text or '')
                if isinstance(parsed, list):
                    return parsed
                return []
            except HTTPError as exc:
                status_code = exc.response.status_code if exc.response is not None else None
                if status_code == 404:
                    last_error = exc
                    continue
                raise

        if last_error is not None:
            raise last_error

        return []


    def members_with_callings_list(self):
        _LOGGER.info("Getting callings for all organizations")
        request = {
            'url': 'https://{}/api/report/members-with-callings'.format(LCR_DOMAIN),
            'params': {'lang': 'eng'}
        }

        try:
            result = self._make_get_request(request)
            return result.json()
        except HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else None
            if status_code != 404:
                raise

        try:
            fallback = self.callings()
            if isinstance(fallback, list):
                return fallback
        except Exception:
            pass

        return []


    def ministering(self):
        """
        API parameters known to be accepted are lang type unitNumber and quarter.
        """
        _LOGGER.info("Getting ministering data")
        request = {
            'url': 'https://{}/api/umlu/v1/ministering/data-full'.format(LCR_DOMAIN),
            'params': {
                'lang': 'eng',
                'unitNumber': self.unit_number,
                'type': 'ALL'
            }
        }

        result = self._make_get_request(request)
        return result.json()


    def access_table(self):
        """
        Once the users role id is known this table could be checked to selectively enable or disable methods for API endpoints.
        """
        _LOGGER.info("Getting info for data access")
        result = self._make_get_request_with_domain_fallback(
            lambda domain: {
                'url': 'https://{}/api/access-table'.format(domain),
                'params': {'lang': 'eng'},
            }
        )
        return self._parse_json_response(result, 'access_table')


    def recommend_status(self):
        """
        Obtain member information on recommend status
        """
        _LOGGER.info("Getting recommend status")
        result = self._make_get_request_with_domain_fallback(
            lambda domain: {
                'url': 'https://{}/api/recommend/recommend-status'.format(domain),
                'params': {
                    'lang': 'eng',
                    'unitNumber': self.unit_number,
                },
            }
        )
        return self._parse_json_response(result, 'recommend_status')


    def unit_details(self, unit_number):
        _LOGGER.info("Getting unit details")
        request = {
            'url': 'https://{}/api/cdol/details/unit/{}'.format(LCR_DOMAIN, unit_number),
            'params': {'lang': 'eng'}
        }
        result = self._make_get_request(request)
        return result.json()


    def accessible_units(self):
        _LOGGER.info("Getting accessible units")
        request = {
            'url': 'https://{}/api/accessible-units'.format(FFE_DOMAIN),
        }
        result = self._make_get_request(request, use_ffe=True)
        return result.json()


    def financial_statement(self, internal_account_id, from_date, to_date):
        graphql_body = {"operationName":"internalTransactionDetailLinesByPostedDate","variables":{"criteria":{"internalAccountIds":[internal_account_id],"postedDateFrom":from_date,"postedDateTo":to_date,"adjustmentCodes":["ACTIVE"],"donationBatchCodes":["ACTIVE"]}},"query":"query internalTransactionDetailLinesByPostedDate($criteria: IntTransDetailLineCriteria!) {\n  internalTransactionDetailLinesByPostedDate(criteria: $criteria) {\n    id\n    postedDate\n    donationSlipLine {\n      id\n      slip {\n        id\n        amount\n        donor {\n          id\n          membershipId\n          names {\n            localUnitDisplayName\n            __typename\n          }\n          birthDate\n          __typename\n        }\n        donation {\n          id\n          date\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    internalAccount {\n      id\n      bus {\n        id\n        currency {\n          id\n          isoCode\n          __typename\n        }\n        __typename\n      }\n      org {\n        id\n        __typename\n      }\n      financialTransactionMethods {\n        id\n        financialTransactionMethod {\n          id\n          financialTransactionType\n          financialTransactionTypeId\n          transactionMethodDescriptionId\n          financialTransactionMethodFinancialInstruments {\n            id\n            financialInstrument {\n              id\n              type\n              typeId\n              __typename\n            }\n            __typename\n          }\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    category {\n      id\n      sortOrder\n      __typename\n    }\n    subcategory {\n      id\n      sortOrder\n      name\n      category {\n        id\n        sortOrder\n        name\n        __typename\n      }\n      __typename\n    }\n    unitSubcategory {\n      id\n      name\n      __typename\n    }\n    amount\n    donationBatch {\n      id\n      date\n      status\n      source\n      submittedBy\n      submittedDate\n      approvedRejectedBy\n      approvedRejectedDate\n      __typename\n    }\n    __typename\n  }\n}\n"}

        _LOGGER.info("Getting financial statement")
        request = {
            'url': 'https://{}/api/graphql'.format(FFE_DOMAIN),
            'json': graphql_body
        }
        result = self._make_post_request(request, use_ffe=True)
        return result.json()


    def financial_participant_list(self, orgId):
        graphql_body = {"operationName":"participants","variables":{"criteria":{"orgIds":[orgId],"status":"ACTIVE"}},"query":"query participants($criteria: ParticipantCriteria!) {\n  participants(criteria: $criteria, maxResults: 10000) {\n    results {\n      id\n      birthDate\n      gender\n      membershipId\n      isMember\n      isDonor\n      isPayee\n      isRecipient\n      taxId\n      address {\n        composed\n        __typename\n      }\n      emailAddress\n      names {\n        localUnitDisplayName\n        __typename\n      }\n      org {\n        id\n        name\n        localName1\n        parent {\n          id\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"}

        _LOGGER.info("Getting financial participant list")
        request = {
            'url': 'https://{}/api/graphql'.format(FFE_DOMAIN),
            'json': graphql_body
        }
        result = self._make_post_request(request, use_ffe=True)
        return result.json()


class MemberData():
    def __init__(self, legacyMemberId, fullName, sex, birthdate, callings, recommendStatus):
        self.legacyMemberId = legacyMemberId
        self.fullName = fullName
        self.sex = sex
        self.birthdate = birthdate
        self.callings = callings
        self.recommendStatus = recommendStatus

    def __iter__(self):
        return iter([self.legacyMemberId, self.fullName, self.sex, self.birthdate, self.callings, self.recommendStatus])

if __name__ == "__main__":
    new_lcr = API("spencermksmith", "6computers", 167371)