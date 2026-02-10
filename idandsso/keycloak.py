#         Copyright (C) 2026 52°North Spatial Information Research GmbH
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     If the program is linked with libraries which are licensed under one
#     of the following licenses, the combination of the program with the
#     linked library is not considered a "derivative work" of the program:
#
#         - Apache License, version 2.0
#         - Apache Software License, version 1.0
#         - GNU Lesser General Public License, version 3
#         - Mozilla Public License, versions 1.0, 1.1 and 2.0
#         - Common Development and Distribution License (CDDL), version 1.0
#
#     Therefore the distribution of the program linked with libraries licensed
#     under the aforementioned licenses, is permitted by the copyright holders
#     if the distribution is compliant with both the GNU General Public License
#     version 2 and the aforementioned licenses.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program. If not, see <https://www.gnu.org/licenses/>.

from allauth.socialaccount.models import SocialAccount
from django.conf import settings
from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakError
from loguru import logger


def add_user_to_keycloak_group(user: settings.AUTH_USER_MODEL, group_name: str) -> bool:
    logger.debug(f"Add User '{user.username}' to group '{group_name}'.")
    kc_user_id = _get_keycloak_user_id_from(user)
    kc_admin = _keycloak_admin()
    kc_group_id = _get_keycloak_group_id_by_name(kc_admin, group_name)

    #
    # https://python-keycloak.readthedocs.io/en/v5.8.1/reference/keycloak/keycloak_admin/index.html#keycloak.keycloak_admin.KeycloakAdmin.group_user_add
    #
    kc_admin.group_user_add(user_id=kc_user_id, group_id=kc_group_id)
    logger.debug(f"Done adding User '{user.username}' to group '{group_name}'.")


def remove_user_from_keycloak_group(user: settings.AUTH_USER_MODEL, group_name: str) -> bool:
    logger.debug(f"Remove User '{user.username}' from group '{group_name}'.")
    kc_user_id = _get_keycloak_user_id_from(user)
    kc_admin = _keycloak_admin()
    kc_group_id = _get_keycloak_group_id_by_name(kc_admin, group_name)

    #
    # https://python-keycloak.readthedocs.io/en/v5.8.1/reference/keycloak/keycloak_admin/index.html#keycloak.keycloak_admin.KeycloakAdmin.group_user_remove
    #
    kc_admin.group_user_remove(user_id=kc_user_id, group_id=kc_group_id)
    logger.debug(f"Done removing User '{user.username}' from group '{group_name}'.")


def _get_keycloak_user_id_from(user: settings.AUTH_USER_MODEL) -> str:
    # throws SocialAccount.DoesNotExist if not found and that is caught in signals._process_sync
    return SocialAccount.objects.get(user=user).uid


def _get_keycloak_group_id_by_name(kc_admin: KeycloakAdmin, group_name: str) -> str:
    found_groups = kc_admin.get_groups({"search": group_name})
    group_id = None
    for group in found_groups:
        if group["name"] == group_name:
            group_id = group["id"]
            break

    if not group_id:
        raise KeycloakError(f"Could not find group by name '{group_name}'")

    return group_id


def _keycloak_admin() -> KeycloakAdmin:
    social_app = settings.SOCIALACCOUNT_PROVIDERS["openid_connect"]["APPS"][0]
    client_id = social_app["client_id"]
    client_secret = social_app["secret"]
    realm = settings.IDANDSSO_PROVIDER_REALM
    server_url = settings.IDANDSSO_PROVIDER_HOST
    return KeycloakAdmin(
        server_url=server_url,
        client_id=client_id,
        client_secret_key=client_secret,
        realm_name=realm,
        user_realm_name=realm,
        verify=not settings.DEBUG,
    )
