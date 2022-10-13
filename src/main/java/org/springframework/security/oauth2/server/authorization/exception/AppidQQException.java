package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * QQ开放平台 AppID 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class AppidQQException extends QQException {

	public AppidQQException(String errorCode) {
		super(errorCode);
	}

	public AppidQQException(OAuth2Error error) {
		super(error);
	}

	public AppidQQException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public AppidQQException(OAuth2Error error, String message) {
		super(error, message);
	}

	public AppidQQException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

}
