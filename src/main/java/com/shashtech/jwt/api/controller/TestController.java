package com.shashtech.jwt.api.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestController {

	//public 
	@GetMapping("/all")
	public String getText() {
		System.out.println("");
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		
		return "working";
	}
	
	//admin
	@GetMapping("/admin")
	@PreAuthorize("hasRole('ADMIN') or hasRole('MODERATOR') or hasRole('USER')")
	public String adminAccess() {
		return "admin access";
	}
	
	@GetMapping("/mod")
	@PreAuthorize("hasRole('MODERATOR')")
	public String modAccess() {
		return "mod access";
	}
	
	@GetMapping("/user")
	@PreAuthorize("hasRole('USER')")
	public String userAccess() {
		return "user access";
	}
}
