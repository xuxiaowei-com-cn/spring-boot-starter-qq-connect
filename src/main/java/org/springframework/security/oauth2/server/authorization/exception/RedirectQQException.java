package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * 重定向 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class RedirectQQException extends QQException {

	public RedirectQQException(String errorCode) {
		super(errorCode);
	}

	public RedirectQQException(OAuth2Error error) {
		super(error);
	}

	public RedirectQQException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public RedirectQQException(OAuth2Error error, String message) {
		super(error, message);
	}

	public RedirectQQException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

}
