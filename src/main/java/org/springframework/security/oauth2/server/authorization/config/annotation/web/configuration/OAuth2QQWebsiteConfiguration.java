package org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.client.InMemoryQQWebsiteService;
import org.springframework.security.oauth2.server.authorization.client.QQWebsiteService;
import org.springframework.security.oauth2.server.authorization.properties.QQWebsiteProperties;

/**
 * QQ开放平台 网站应用 配置
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Configuration
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2QQWebsiteConfiguration {

	private QQWebsiteProperties qqWebsiteProperties;

	@Autowired
	public void setQqWebsiteProperties(QQWebsiteProperties qqWebsiteProperties) {
		this.qqWebsiteProperties = qqWebsiteProperties;
	}

	@Bean
	@ConditionalOnMissingBean
	public QQWebsiteService qqWebsiteService() {
		return new InMemoryQQWebsiteService(qqWebsiteProperties);
	}

}
