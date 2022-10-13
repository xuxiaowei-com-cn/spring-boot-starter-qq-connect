package org.springframework.security.oauth2.server.authorization.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * QQ开放平台 网站应用 属性配置类
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Data
@Component
@ConfigurationProperties("qq.website")
public class QQWebsiteProperties {

	/**
	 * QQ开放平台 网站应用 属性配置列表
	 */
	private List<QQWebsite> list;

	/**
	 * 默认QQ开放平台 网站应用 的权限
	 */
	private String defaultRole;

	/**
	 * QQ开放平台 网站应用 属性配置类
	 *
	 * @author xuxiaowei
	 * @since 0.0.1
	 */
	@Data
	public static class QQWebsite {

		/**
		 * AppID
		 */
		private String appid;

		/**
		 * AppSecret
		 */
		private String secret;

		/**
		 * 重定向的网址前缀（程序使用时，会在后面拼接 /{@link #appid}）
		 */
		private String redirectUriPrefix;

		/**
		 * OAuth2 客户ID
		 */
		private String clientId;

		/**
		 * OAuth2 客户秘钥
		 */
		private String clientSecret;

		/**
		 * 获取 Token URL 前缀
		 */
		private String tokenUrlPrefix;

		/**
		 * 授权范围
		 */
		private String scope;

		/**
		 * 登录成功后重定向的URL
		 */
		private String successUrl;

		/**
		 * 登录成功后重定向的URL OAuth2.1 授权 Token Name
		 */
		private String parameterName = "access_token";

	}

}
