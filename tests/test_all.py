import os

import pytest
from selenium.common.exceptions import SessionNotCreatedException, WebDriverException
from requests.exceptions import HTTPError

import lcr


def _require_env(name):
    value = os.getenv(name)
    if not value:
        pytest.skip(f"Missing required environment variable: {name}")
    return value


def _assert_required_keys(required, actual):
    missing = required - actual
    if missing:
        message = f"Missing required keys: {missing}\n"
        message += f"Actual keys: {actual}\n"
        raise AssertionError(message)


def _find_first_value(obj, candidate_keys):
    if isinstance(obj, dict):
        for key in candidate_keys:
            value = obj.get(key)
            if value:
                return value
        for value in obj.values():
            found = _find_first_value(value, candidate_keys)
            if found:
                return found
    if isinstance(obj, list):
        for item in obj:
            found = _find_first_value(item, candidate_keys)
            if found:
                return found
    return None


def _call_or_skip(fn, endpoint_name):
    try:
        return fn()
    except lcr.EndpointUnavailableError as exc:
        pytest.skip(f"Endpoint unavailable: {endpoint_name} ({exc})")
    except HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else "unknown"
        pytest.skip(f"Endpoint HTTP error: {endpoint_name} (status={status_code})")


class TestLiveApiE2E:
    @classmethod
    def setup_class(cls):
        user = _require_env("LDS_USER")
        password = _require_env("LDS_PASSWORD")
        unit_number = _require_env("LDS_UNIT_NUMBER")
        cls.unit_number = unit_number
        try:
            cls.cd = lcr.API(user, password, unit_number)
        except SessionNotCreatedException as exc:
            pytest.skip(f"E2E setup skipped: webdriver/browser mismatch ({exc})")
        except WebDriverException as exc:
            pytest.skip(f"E2E setup skipped: webdriver unavailable ({exc})")

    def test_birthday(self):
        birthdays_result = _call_or_skip(lambda: self.cd.birthday_list(4, 1), "birthday_list")
        assert isinstance(birthdays_result, list)
        assert birthdays_result

        birthdays = birthdays_result[0]["birthdays"]
        assert isinstance(birthdays, list)
        assert birthdays

        birthday = birthdays[0]
        assert isinstance(birthday, dict)

        expected_keys = {
            "name", "spokenName", "nameOrder", "birthDate",
            "birthDateSort", "birthDaySort", "birthDayFormatted",
            "birthDateFormatted", "gender", "genderCode", "mrn", "id",
            "email", "householdEmail", "phone", "householdPhone",
            "unitNumber", "unitName", "priesthood", "priesthoodCode",
            "priesthoodType", "age", "actualAge", "actualAgeInMonths",
            "genderLabelShort", "visible", "nonMember", "outOfUnitMember",
            "notAccountable", "address", "monthInteger", "dayInteger",
            "birthDayAge", "displayBirthdate", "sustainedDate",
            "formattedMrn", "setApart", "accountable",
        }
        _assert_required_keys(expected_keys, set(birthday.keys()))

    def test_moveins(self):
        moveins = _call_or_skip(lambda: self.cd.members_moved_in(5), "members_moved_in")
        assert isinstance(moveins, list)
        assert moveins

        movein = moveins[0]
        assert isinstance(movein, dict)

        expected_keys = {
            "gender", "phone", "moveDateCalc", "nameOrder",
            "genderLabelShort", "priesthood", "addressUnknown",
            "birthdate", "birthdateCalc", "moveDate", "unitName",
            "priorUnitNumber", "address", "id", "householdPositionEnum",
            "priorUnitName", "moveDateOrder", "textAddress", "locale",
            "householdUuid", "householdPosition", "name", "age",
        }
        _assert_required_keys(expected_keys, set(movein.keys()))

    def test_moveouts(self):
        moveouts = _call_or_skip(lambda: self.cd.members_moved_out(5), "members_moved_out")
        assert isinstance(moveouts, list)
        assert moveouts

        moveout = moveouts[0]
        assert isinstance(moveout, dict)

        expected_keys = {
            "deceased", "nextUnitNumber", "name", "nextUnitName",
            "addressUnknown", "moveDate", "priorUnit",
            "moveDateOrder", "birthDate", "nameOrder",
        }
        _assert_required_keys(expected_keys, set(moveout.keys()))

    def test_member_list_and_member_profile_and_photo(self):
        member_list = self.cd.member_list()
        assert isinstance(member_list, list)
        assert member_list

        member = member_list[0]
        assert isinstance(member, dict)

        expected_keys = {
            "nameFormats", "uuid", "nameOrder", "age", "emails", "phones",
            "phoneNumber", "priesthoodOffice", "membershipUnit",
            "legacyCmisId", "sex", "unitOrgsCombined", "positions",
            "householdMember", "formattedAddress",
            "isMember", "householdUuid", "isProspectiveElder",
            "isSingleAdult", "isYoungSingleAdult",
            "isHead", "priesthoodTeacherOrAbove", "convert", "member",
            "unitName", "youthBasedOnAge", "isSpouse", "unitNumber",
            "outOfUnitMember", "nameGivenPreferredLocal",
            "houseHoldMemberNameForList", "isOutOfUnitMember", "isAdult",
            "nameFamilyPreferredLocal", "householdAnchorPersonUuid",
            "householdNameFamilyLocal", "householdRole", "personUuid",
            "nameListPreferredLocal", "householdNameDirectoryLocal",
            "email", "address", "birth", "personStatusFlags",
        }
        _assert_required_keys(expected_keys, set(member.keys()))

        member_id = member.get("personUuid") or member.get("id")
        if not member_id:
            birthdays = self.cd.birthday_list(4, 1)
            birthday_rows = birthdays[0].get("birthdays", []) if birthdays else []
            if birthday_rows:
                member_id = birthday_rows[0].get("id")

        if not member_id:
            pytest.skip("Could not determine member_id for member_profile/individual_photo test")

        profile = _call_or_skip(lambda: self.cd.member_profile(member_id), "member_profile")
        assert isinstance(profile, dict)
        assert profile

        photo = self.cd.individual_photo(member_id)
        assert isinstance(photo, (bytes, bytearray))
        assert len(photo) > 0

    def test_callings_and_members_with_callings(self):
        callings = _call_or_skip(lambda: self.cd.callings(), "callings")
        assert isinstance(callings, list)

        members_with_callings = self.cd.members_with_callings_list()
        assert isinstance(members_with_callings, list)

    def test_ministering(self):
        ministering = self.cd.ministering()
        assert isinstance(ministering, dict)
        assert isinstance(ministering.get("elders"), list)
        assert isinstance(ministering.get("reliefSociety"), list)

    def test_access_table(self):
        access_table = self.cd.access_table()
        assert isinstance(access_table, dict)
        assert access_table

    def test_recommend_status(self):
        recommend_status = _call_or_skip(lambda: self.cd.recommend_status(), "recommend_status")
        assert isinstance(recommend_status, list)
        assert recommend_status

        member = recommend_status[0]
        assert isinstance(member, dict)

        expected_keys = {
            "name", "spokenName", "nameOrder", "birthDate",
            "birthDateSort", "birthDaySort", "birthDayFormatted",
            "birthDateFormatted", "gender", "genderCode", "mrn", "id",
            "email", "householdEmail", "phone", "householdPhone",
            "unitNumber", "unitName", "priesthood", "priesthoodCode",
            "priesthoodType", "age", "actualAge", "actualAgeInMonths",
            "genderLabelShort", "visible", "nonMember", "outOfUnitMember",
            "notAccountable", "marriageDate", "endowmentDate",
            "expirationDate", "status", "recommendStatus", "type",
            "unordained", "notBaptized", "recommendStatusSimple",
            "recommendEditable", "formattedMrn", "sustainedDate",
            "accountable", "setApart",
        }
        _assert_required_keys(expected_keys, set(member.keys()))

    def test_unit_details(self):
        unit_details = self.cd.unit_details(self.unit_number)
        assert isinstance(unit_details, dict)
        assert unit_details

    def test_accessible_units(self):
        accessible_units = self.cd.accessible_units()
        assert isinstance(accessible_units, (dict, list))

    def test_financial_endpoints(self):
        accessible_units = self.cd.accessible_units()

        org_id = os.getenv("LCR_TEST_FINANCIAL_ORG_ID")
        account_id = os.getenv("LCR_TEST_FINANCIAL_ACCOUNT_ID")

        if not org_id:
            org_id = _find_first_value(accessible_units, ["orgId", "organizationId", "org_id"])
        if not account_id:
            account_id = _find_first_value(
                accessible_units,
                ["internalAccountId", "internal_account_id", "accountId", "account_id"],
            )

        if not org_id or not account_id:
            pytest.skip(
                "Financial endpoint test needs org/account IDs. "
                "Set LCR_TEST_FINANCIAL_ORG_ID and LCR_TEST_FINANCIAL_ACCOUNT_ID."
            )

        from_date = os.getenv("LCR_TEST_FINANCIAL_FROM_DATE", "2025-01-01")
        to_date = os.getenv("LCR_TEST_FINANCIAL_TO_DATE", "2025-01-31")

        statement = self.cd.financial_statement(account_id, from_date, to_date)
        assert isinstance(statement, dict)

        participants = self.cd.financial_participant_list(org_id)
        assert isinstance(participants, dict)
