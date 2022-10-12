package org.springframework.security.oauth2.server.authorization.http;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2QQParameterNames;
import org.springframework.security.oauth2.server.authorization.client.QQWebsiteService;
import org.springframework.security.oauth2.server.authorization.properties.QQWebsiteProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * QQ开放平台 网站应用 跳转到QQ授权页面
 *
 * @see <a href=
 * "https://wiki.connect.qq.com/%e4%bd%bf%e7%94%a8authorization_code%e8%8e%b7%e5%8f%96access_token">使用Authorization_Code获取Access_Token</a>
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

			String binding = request.getParameter(OAuth2QQParameterNames.BINDING);
			String scope = request.getParameter(OAuth2ParameterNames.SCOPE);

			String state = qqWebsiteService.stateGenerate(request, response, appid);
			qqWebsiteService.storeBinding(request, response, appid, state, binding);
			qqWebsiteService.storeUsers(request, response, appid, state, binding);

			String url = String.format(AUTHORIZE_URL, appid, redirectUri, scope, state);

			log.info("redirectUrl：{}", url);

			response.sendRedirect(url);
			return;
		}

		super.doFilter(request, response, chain);
	}

}
