package com.shashtech.jwt.api.response;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtResponse {
	
	private String token;
	private String type="Bearer";
	private String refreshToken;
	private String email;
	private Integer id;
	
	private List<String> userRoles;

}
