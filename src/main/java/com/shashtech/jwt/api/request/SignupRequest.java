package com.shashtech.jwt.api.request;

import java.util.Set;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignupRequest {
	
	@NotBlank
	@Size(min=3,max=20)
	private String userName;
	
	@NotBlank
	@Size(max=50)
	@Email
	private String email;
	
	@NotBlank
	@Size(min=8,max=20)
	private String password;
	
	private Set<String> role;
}
