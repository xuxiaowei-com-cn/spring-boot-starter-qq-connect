package org.springframework.security.oauth2.server.authorization.client;

/*-
 * #%L
 * spring-boot-starter-qq-connect
 * %%
 * Copyright (C) 2022 徐晓伟工作室
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.io.Serializable;

/**
 * 通过 code 换取网页授权 access_token 返回值
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see <a href=
 * "https://wiki.connect.qq.com/%e4%bd%bf%e7%94%a8authorization_code%e8%8e%b7%e5%8f%96access_token">使用Authorization_Code获取Access_Token</a>
 */
@Data
public class QQWebsiteTokenResponse implements Serializable {

	private static final long serialVersionUID = 1L;

	/**
	 * 网页授权接口调用凭证,注意：此access_token与基础支持的access_token不同
	 */
	@JsonProperty("access_token")
	private String accessToken;

	/**
	 * access_token接口调用凭证超时时间，单位（秒）
	 */
	@JsonProperty("expires_in")
	private Integer expiresIn;

	/**
	 * 用户刷新access_token
	 */
	@JsonProperty("refresh_token")
	private String refreshToken;

	/**
	 * 错误码
	 */
	private String error;

	/**
	 * 错误信息
	 */
	@JsonProperty("error_description")
	private String errorDescription;

	////

	/**
	 * 客户ID
	 */
	@JsonProperty("client_id")
	private String clientId;

	/**
	 * 用户唯一标识
	 */
	private String openid;

	/**
	 * @see <a href="https://wiki.connect.qq.com/unionid%E4%BB%8B%E7%BB%8D">UnionID介绍</a>
	 */
	private String unionid;

	////

	private int ret;

	private String msg;

	@JsonProperty("is_lost")
	private int isLost;

	private String gender;

	@JsonProperty("is_yellow_vip")
	private String isYellowVip;

	private String city;

	private String year;

	private String level;

	@JsonProperty("figureurl_2")
	private String figureurl2;

	@JsonProperty("figureurl_1")
	private String figureurl1;

	@JsonProperty("gender_type")
	private int genderType;

	@JsonProperty("is_yellow_year_vip")
	private String isYellowYearVip;

	private String province;

	private String constellation;

	private String figureurl;

	@JsonProperty("figureurl_type")
	private String figureurlType;

	@JsonProperty("figureurl_qq")
	private String figureurlQq;

	private String nickname;

	@JsonProperty("yellow_vip_level")
	private String yellowVipLevel;

	@JsonProperty("figureurl_qq_1")
	private String figureurlQq1;

	private String vip;

	@JsonProperty("figureurl_qq_2")
	private String figureurlQq2;

}
