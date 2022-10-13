package org.springframework.security.oauth2.server.authorization.authentication;

import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.QQWebsiteService;
import org.springframework.security.oauth2.server.authorization.client.QQWebsiteTokenResponse;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2QQWebsiteConfigurerUtils;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.properties.QQWebsiteProperties;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.security.Principal;
import java.util.Map;
import java.util.Set;

/**
 * QQ开放平台 网站应用 OAuth2 身份验证提供程序
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see AnonymousAuthenticationProvider
 * @see JwtClientAssertionAuthenticationProvider
 * @see ClientSecretAuthenticationProvider
 * @see PublicClientAuthenticationProvider
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 * @see OAuth2AuthorizationCodeAuthenticationProvider
 * @see OAuth2RefreshTokenAuthenticationProvider
 * @see OAuth2ClientCredentialsAuthenticationProvider
 * @see OAuth2TokenIntrospectionAuthenticationProvider
 * @see OAuth2TokenRevocationAuthenticationProvider
 * @see OidcUserInfoAuthenticationProvider
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2QQWebsiteAuthenticationProvider implements AuthenticationProvider {

	/**
	 * @see OAuth2TokenContext#getAuthorizedScopes()
	 */
	private static final String AUTHORIZED_SCOPE_KEY = OAuth2Authorization.class.getName().concat(".AUTHORIZED_SCOPE");

	/**
	 * @see <a href=
	 * "https://wiki.connect.qq.com/%e4%bd%bf%e7%94%a8authorization_code%e8%8e%b7%e5%8f%96access_token">使用Authorization_Code获取Access_Token</a>
	 */
	public static final String ACCESS_TOKEN_URL = "https://graph.qq.com/oauth2.0/token"
			+ "?grant_type=authorization_code&client_id={client_id}&redirect_uri={redirect_uri}&client_secret={client_secret}&code={code}&fmt=json";

	/**
	 * @see <a href=
	 * "https://wiki.connect.qq.com/%e8%8e%b7%e5%8f%96%e7%94%a8%e6%88%b7openid_oauth2-0">获取用户OpenID_OAuth2.0</a>
	 */
	public static final String OPENID_URL = "https://graph.qq.com/oauth2.0/me?access_token={access_token}&fmt=json";

	/**
	 * @see <a href="https://wiki.connect.qq.com/unionid%E4%BB%8B%E7%BB%8D">UnionID介绍</a>
	 */
	public static final String UNIONID_URL = "https://graph.qq.com/oauth2.0/me?access_token=EA813ACE5FCDCE4100784A8611F17DCC&unionid=1&fmt=json";

	/**
	 * @see <a href=
	 * "https://wiki.connect.qq.com/%e4%bd%bf%e7%94%a8authorization_code%e8%8e%b7%e5%8f%96access_token">使用Authorization_Code获取Access_Token</a>
	 */
	public static final String USERINFO_URL = "https://graph.qq.com/user/get_user_info?openid={openid}&access_token={access_token}&oauth_consumer_key={client_id}";

	private final HttpSecurity builder;

	@Setter
	private OAuth2AuthorizationService authorizationService;

	@Setter
	private OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

	@Setter
	private QQWebsiteService qqWebsiteService;

	public OAuth2QQWebsiteAuthenticationProvider(HttpSecurity builder) {
		Assert.notNull(builder, "HttpSecurity 不能为空");
		this.builder = builder;
		builder.authenticationProvider(this);
	}

	@SuppressWarnings("AlibabaMethodTooLong")
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		// 初始化变量默认值
		variableDefaults();

		OAuth2QQWebsiteAuthenticationToken grantAuthenticationToken = (OAuth2QQWebsiteAuthenticationToken) authentication;

		String appid = grantAuthenticationToken.getAppid();
		String code = grantAuthenticationToken.getCode();
		String state = grantAuthenticationToken.getState();
		String binding = grantAuthenticationToken.getBinding();

		Map<String, Object> additionalParameters = grantAuthenticationToken.getAdditionalParameters();
		Set<String> requestedScopes = StringUtils.commaDelimitedListToSet(grantAuthenticationToken.getScope());

		OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils
				.getAuthenticatedClientElseThrowInvalidClient(grantAuthenticationToken);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		// 自定义QQ开放平台 网站应用用户的IP与SessionId
		String remoteAddress = grantAuthenticationToken.getRemoteAddress();
		String sessionId = grantAuthenticationToken.getSessionId();
		sessionId = "".equals(sessionId) ? null : sessionId;
		WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetails(remoteAddress, sessionId);
		clientPrincipal.setDetails(webAuthenticationDetails);

		if (registeredClient == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "注册客户不能为空", null);
			throw new OAuth2AuthenticationException(error);
		}

		Set<String> allowedScopes = registeredClient.getScopes();

		if (requestedScopes.isEmpty()) {
			// 请求中的 scope 为空，允许全部
			requestedScopes = allowedScopes;
		}
		else if (!allowedScopes.containsAll(requestedScopes)) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE,
					"OAuth 2.0 参数: " + OAuth2ParameterNames.SCOPE, null);
			throw new OAuth2AuthenticationException(error);
		}

		QQWebsiteProperties.QQWebsite qqWebsite = qqWebsiteService.getQQWebsiteByAppid(appid);
		String redirectUri = qqWebsite.getRedirectUriPrefix() + "/" + appid;

		QQWebsiteTokenResponse qqWebsiteTokenResponse = qqWebsiteService.getAccessTokenResponse(appid, code, state,
				binding, redirectUri, ACCESS_TOKEN_URL, OPENID_URL, UNIONID_URL, USERINFO_URL, remoteAddress,
				sessionId);

		String openid = qqWebsiteTokenResponse.getOpenid();
		String unionid = qqWebsiteTokenResponse.getUnionid();

		String accessToken = qqWebsiteTokenResponse.getAccessToken();
		String refreshToken = qqWebsiteTokenResponse.getRefreshToken();
		Integer expiresIn = qqWebsiteTokenResponse.getExpiresIn();

		OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient);
		builder.principalName(openid);
		builder.authorizationGrantType(OAuth2QQWebsiteAuthenticationToken.QQ_WEBSITE);

		AbstractAuthenticationToken abstractAuthenticationToken = qqWebsiteService.authenticationToken(clientPrincipal,
				additionalParameters, grantAuthenticationToken.getDetails(), appid, code, openid, null, unionid,
				accessToken, refreshToken, expiresIn);

		builder.attribute(Principal.class.getName(), abstractAuthenticationToken);
		builder.attribute(AUTHORIZED_SCOPE_KEY, requestedScopes);

		OAuth2Authorization authorization = builder.build();

		// @formatter:off
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(authorization.getAttribute(Principal.class.getName()))
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorization(authorization)
				.authorizedScopes(authorization.getAttribute(AUTHORIZED_SCOPE_KEY))
				.authorizationGrantType(OAuth2QQWebsiteAuthenticationToken.QQ_WEBSITE)
				.authorizationGrant(grantAuthenticationToken);
		// @formatter:on

		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);

		// ----- Access token -----
		OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
		OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContext);
		if (generatedAccessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the access token.", null);
			throw new OAuth2AuthenticationException(error);
		}
		OAuth2AccessToken oauth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
				generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
		if (generatedAccessToken instanceof ClaimAccessor) {
			authorizationBuilder.token(oauth2AccessToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
							((ClaimAccessor) generatedAccessToken).getClaims()));
		}
		else {
			authorizationBuilder.accessToken(oauth2AccessToken);
		}

		// ----- Refresh token -----
		OAuth2RefreshToken oauth2RefreshToken = null;
		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
		// Do not issue refresh token to public client
				!clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {

			tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
			OAuth2Token generatedRefreshToken = tokenGenerator.generate(tokenContext);
			if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "令牌生成器无法生成刷新令牌。", null);
				throw new OAuth2AuthenticationException(error);
			}
			oauth2RefreshToken = (OAuth2RefreshToken) generatedRefreshToken;
			authorizationBuilder.refreshToken(oauth2RefreshToken);
		}

		authorization = authorizationBuilder.build();

		authorizationService.save(authorization);

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, oauth2AccessToken,
				oauth2RefreshToken, additionalParameters);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2QQWebsiteAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * 初始化变量默认值
	 */
	private void variableDefaults() {
		if (authorizationService == null) {
			authorizationService = OAuth2QQWebsiteConfigurerUtils.getAuthorizationService(builder);
		}

		if (tokenGenerator == null) {
			tokenGenerator = OAuth2QQWebsiteConfigurerUtils.getTokenGenerator(builder);
		}

		if (qqWebsiteService == null) {
			qqWebsiteService = OAuth2QQWebsiteConfigurerUtils.getQqWebsiteService(builder);
		}
	}

}
