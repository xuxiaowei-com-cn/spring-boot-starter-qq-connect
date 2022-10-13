package org.springframework.security.oauth2.server.authorization.web.authentication;

/**
 * QQ开放平台 网站应用 OAuth 2.0 协议端点的实用方法
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2QQWebsiteEndpointUtils {

	/**
	 * QQ开放平台 网站应用
	 */
	public static final String AUTH_CODE2SESSION_URI = "https://wiki.connect.qq.com/%e4%bd%bf%e7%94%a8authorization_code%e8%8e%b7%e5%8f%96access_token";

	/**
	 * 获取用户OpenID_OAuth2.0
	 */
	public static final String AUTH_OPENID_URI = "https://wiki.connect.qq.com/%e8%8e%b7%e5%8f%96%e7%94%a8%e6%88%b7openid_oauth2-0";

	/**
	 * get_user_info
	 */
	public static final String AUTH_USER_INFO_URI = "https://wiki.connect.qq.com/get_user_info";

	/**
	 * 错误代码
	 */
	public static final String ERROR_CODE = "C10000";

	/**
	 * 无效错误代码
	 */
	public static final String INVALID_ERROR_CODE = "C20000";

}
