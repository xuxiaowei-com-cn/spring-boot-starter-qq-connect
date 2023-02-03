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

import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2QQWebsiteParameterNames;
import org.springframework.security.oauth2.server.authorization.client.QQWebsiteService;
import org.springframework.security.oauth2.server.authorization.properties.QQWebsiteProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * QQ开放平台 网站应用 跳转到QQ授权页面
 *
 * @see <a href=
 * "https://wiki.connect.qq.com/%e4%bd%bf%e7%94%a8authorization_code%e8%8e%b7%e5%8f%96access_token">使用Authorization_Code获取Access_Token</a>
 * @see <a href="https://connect.qq.com/sdk/webtools/index.html">API调试工具</a>
 * @author xuxiaowei
 * @since 0.0.1
 */
@Slf4j
@Data
@EqualsAndHashCode(callSuper = true)
@Component
public class QQWebsiteAuthorizeHttpFilter extends HttpFilter {

	public static final String PREFIX_URL = "/qq/website/authorize";

	public static final String AUTHORIZE_URL = "https://graph.qq.com/oauth2.0/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s";

	public static final String GET_USER_INFO = "get_user_info";

	public static final String ADD_TOPIC = "add_topic";

	public static final String ADD_ONE_BLOG = "add_one_blog";

	public static final String ADD_ALBUM = "add_album";

	public static final String UPLOAD_PIC = "upload_pic";

	public static final String LIST_ALBUM = "list_album";

	public static final String ADD_SHARE = "add_share";

	public static final String CHECK_PAGE_FANS = "check_page_fans";

	public static final String GET_TENPAY_ADDR = "get_tenpay_addr";

	private QQWebsiteProperties qqWebsiteProperties;

	private QQWebsiteService qqWebsiteService;

	/**
	 * QQ开放平台 网站应用 授权前缀
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

			String redirectUri = qqWebsiteService.getRedirectUriByAppid(appid);

			String binding = request.getParameter(OAuth2QQWebsiteParameterNames.BINDING);
			String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
			String scopeResult;
			if (scope == null) {
				scopeResult = GET_USER_INFO;
			}
			else {
				List<String> scopeList = Splitter.on(",").trimResults().splitToList(scope);
				List<String> legalList = Arrays.asList(GET_USER_INFO, ADD_TOPIC, ADD_ONE_BLOG, ADD_ALBUM, UPLOAD_PIC,
						LIST_ALBUM, ADD_SHARE, CHECK_PAGE_FANS, GET_TENPAY_ADDR);
				Set<String> scopeResultSet = new HashSet<>();
				scopeResultSet.add(GET_USER_INFO);
				for (String sc : scopeList) {
					if (legalList.contains(sc)) {
						scopeResultSet.add(sc);
					}
				}
				scopeResult = Joiner.on(",").join(scopeResultSet);
			}

			String state = qqWebsiteService.stateGenerate(request, response, appid);
			qqWebsiteService.storeBinding(request, response, appid, state, binding);
			qqWebsiteService.storeUsers(request, response, appid, state, binding);

			String url = String.format(AUTHORIZE_URL, appid, redirectUri, scopeResult, state);

			log.info("redirectUrl：{}", url);

			response.sendRedirect(url);
			return;
		}

		super.doFilter(request, response, chain);
	}

}
