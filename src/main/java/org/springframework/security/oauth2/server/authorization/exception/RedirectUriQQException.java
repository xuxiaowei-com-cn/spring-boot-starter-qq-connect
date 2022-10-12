package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * QQ开放平台 redirectUri 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class RedirectUriQQException extends QQException {

	public RedirectUriQQException(String errorCode) {
		super(errorCode);
	}

	public RedirectUriQQException(OAuth2Error error) {
		super(error);
	}

	public RedirectUriQQException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public RedirectUriQQException(OAuth2Error error, String message) {
		super(error, message);
	}

	public RedirectUriQQException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

}
