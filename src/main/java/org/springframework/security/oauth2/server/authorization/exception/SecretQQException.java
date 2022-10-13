package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * QQ开放平台 Secret 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class SecretQQException extends QQException {

	public SecretQQException(String errorCode) {
		super(errorCode);
	}

	public SecretQQException(OAuth2Error error) {
		super(error);
	}

	public SecretQQException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public SecretQQException(OAuth2Error error, String message) {
		super(error, message);
	}

	public SecretQQException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

}
