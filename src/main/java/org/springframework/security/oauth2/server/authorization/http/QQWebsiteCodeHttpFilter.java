package org.springframework.security.oauth2.server.authorization.http;

/*-
 * #%L
 * spring-boot-starter-qq-connect
 * %%
 * Copyright (C) 2022 徐晓伟工作室
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.*;
import org.springframework.security.oauth2.server.authorization.client.QQWebsiteService;
import org.springframework.security.oauth2.server.authorization.properties.QQWebsiteProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2QQWebsiteAuthenticationToken.QQ_WEBSITE;

/**
 * QQ开放平台 网站应用 授权码接收服务
 *
 * @see <a href=
 * "https://wiki.connect.qq.com/%e4%bd%bf%e7%94%a8authorization_code%e8%8e%b7%e5%8f%96access_token">使用Authorization_Code获取Access_Token</a>
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2AccessTokenResponse
 * @see DefaultOAuth2AccessTokenResponseMapConverter
 * @see DefaultMapOAuth2AccessTokenResponseConverter
 */
@Slf4j
@Data
@EqualsAndHashCode(callSuper = true)
@Component
public class QQWebsiteCodeHttpFilter extends HttpFilter {

	public static final String PREFIX_URL = "/qq/website/code";

	public static final String TOKEN_URL = "/oauth2/token?grant_type={grant_type}&appid={appid}&code={code}&state={state}&client_id={client_id}&client_secret={client_secret}&remote_address={remote_address}&session_id={session_id}&binding={binding}";

	private QQWebsiteProperties qqWebsiteProperties;

	private QQWebsiteService qqWebsiteService;

	/**
	 * QQ开放平台 网站应用 使用code获取授权凭证URL前缀
	 */
	private String prefixUrl = PREFIX_URL;

	@Autowired
	public void setQqWebsiteProperties(QQWebsiteProperties qqWebsiteProperties) {
		this.qqWebsiteProperties = qqWebsiteProperties;
	}

	@Autowired
	public void setQqWebsiteService(QQWebsiteService qqWebsiteService) {
		this.qqWebsiteService = qqWebsiteService;
	}

	@Override
	protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String requestUri = request.getRequestURI();
		AntPathMatcher antPathMatcher = new AntPathMatcher();
		boolean match = antPathMatcher.match(prefixUrl + "/*", requestUri);
		if (match) {
			log.info("requestUri：{}", requestUri);

			String appid = requestUri.replace(prefixUrl + "/", "");
			String code = request.getParameter(OAuth2ParameterNames.CODE);
			String state = request.getParameter(OAuth2ParameterNames.STATE);
			String grantType = QQ_WEBSITE.getValue();

			boolean valid = qqWebsiteService.stateValid(request, response, appid, code, state);
			if (!valid) {
				return;
			}

			String binding = qqWebsiteService.getBinding(request, response, appid, code, state);

			QQWebsiteProperties.QQWebsite qqWebsite = qqWebsiteService.getQQWebsiteByAppid(appid);

			String clientId = qqWebsite.getClientId();
			String clientSecret = qqWebsite.getClientSecret();
			String tokenUrlPrefix = qqWebsite.getTokenUrlPrefix();
			String scope = qqWebsite.getScope();

			String remoteHost = request.getRemoteHost();
			HttpSession session = request.getSession(false);

			Map<String, String> uriVariables = new HashMap<>(8);
			uriVariables.put(OAuth2ParameterNames.GRANT_TYPE, grantType);
			uriVariables.put(OAuth2QQWebsiteParameterNames.APPID, appid);
			uriVariables.put(OAuth2ParameterNames.CODE, code);
			uriVariables.put(OAuth2ParameterNames.STATE, state);
			uriVariables.put(OAuth2ParameterNames.SCOPE, scope);
			uriVariables.put(OAuth2ParameterNames.CLIENT_ID, clientId);
			uriVariables.put(OAuth2ParameterNames.CLIENT_SECRET, clientSecret);
			uriVariables.put(OAuth2QQWebsiteParameterNames.REMOTE_ADDRESS, remoteHost);
			uriVariables.put(OAuth2QQWebsiteParameterNames.SESSION_ID, session == null ? "" : session.getId());
			uriVariables.put(OAuth2QQWebsiteParameterNames.BINDING, binding);

			OAuth2AccessTokenResponse oauth2AccessTokenResponse = qqWebsiteService.getOAuth2AccessTokenResponse(request,
					response, tokenUrlPrefix, TOKEN_URL, uriVariables);
			if (oauth2AccessTokenResponse == null) {
				return;
			}

			qqWebsiteService.sendRedirect(request, response, uriVariables, oauth2AccessTokenResponse, qqWebsite);
			return;
		}

		super.doFilter(request, response, chain);
	}

}
