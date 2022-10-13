package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryQQWebsiteService;
import org.springframework.security.oauth2.server.authorization.client.QQWebsiteService;
import org.springframework.security.oauth2.server.authorization.properties.QQWebsiteProperties;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * QQ开放平台 网站应用 OAuth 2.0 配置器的实用方法。
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2ConfigurerUtils
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2QQWebsiteConfigurerUtils {

	public static OAuth2AuthorizationService getAuthorizationService(HttpSecurity httpSecurity) {
		return OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity);
	}

	public static OAuth2TokenGenerator<? extends OAuth2Token> getTokenGenerator(HttpSecurity httpSecurity) {
		return OAuth2ConfigurerUtils.getTokenGenerator(httpSecurity);
	}

	public static QQWebsiteService getQqWebsiteService(HttpSecurity httpSecurity) {
		QQWebsiteService qqWebsiteService = httpSecurity.getSharedObject(QQWebsiteService.class);
		if (qqWebsiteService == null) {
			qqWebsiteService = OAuth2ConfigurerUtils.getOptionalBean(httpSecurity, QQWebsiteService.class);
			if (qqWebsiteService == null) {
				QQWebsiteProperties qqWebsiteProperties = OAuth2ConfigurerUtils.getOptionalBean(httpSecurity,
						QQWebsiteProperties.class);
				qqWebsiteService = new InMemoryQQWebsiteService(qqWebsiteProperties);
			}
		}
		return qqWebsiteService;
	}

}
