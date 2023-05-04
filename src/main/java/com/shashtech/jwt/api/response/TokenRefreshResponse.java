package com.shashtech.jwt.api.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenRefreshResponse {

	private String accessToken;
	private String refreshToken;
	private String type="Bearer";
}
