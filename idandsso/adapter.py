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

import requests
from allauth.account.adapter import DefaultAccountAdapter
from django.conf import settings
from django.utils.http import urlencode
from loguru import logger


class KeycloakOrcidAccountAdapter(DefaultAccountAdapter):
    def get_logout_redirect_url(self, request):
        social_app = settings.SOCIALACCOUNT_PROVIDERS["openid_connect"]["APPS"][0]
        client_id = social_app["client_id"]
        client_secret = social_app["secret"]
        oidc_endpoint = social_app["settings"]["oidc_endpoint"]
        if request.POST.get("range") == "idp-only":
            post_logout_redirect_uri = settings.LOGIN_REDIRECT_URL
        else:
            post_logout_redirect_uri = settings.SOCIALACCOUNT_LOGOUT_REDIRECT_URL
        logger.debug(
            f"Received range: '{request.POST.get('range')}', hence post logout redirect url: '{post_logout_redirect_uri}'"
        )
        params = {
            "client_id": client_id,
            "post_logout_redirect_uri": post_logout_redirect_uri,
        }

        token_endpoint = f"{oidc_endpoint}token"
        logger.debug(f"Requesting id token from '{token_endpoint}'")
        res = requests.post(
            token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "openid",
            },
            timeout=5,
        )
        if res.status_code != 200:
            logger.error(
                f"Could not retrieve id_token for user '{request.user.username}'. Code: '{res.status_code}'. Content: '{str(res.content)}'"
            )
        else:
            res_json = res.json()
            params["id_token_hint"] = res_json["id_token"]

        logout_url = f"{oidc_endpoint}logout?{urlencode(params)}"
        logger.debug(f"Logout URL generated '{logout_url}'")
        return logout_url
