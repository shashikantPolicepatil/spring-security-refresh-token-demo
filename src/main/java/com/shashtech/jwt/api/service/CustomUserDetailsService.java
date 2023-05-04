package com.shashtech.jwt.api.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.shashtech.jwt.api.entity.User;
import com.shashtech.jwt.api.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private UserRepository userRepo;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepo.findByUserName(username)
				.orElseThrow(()-> new UsernameNotFoundException("User not found with username"));
		return UserDetailsServiceImpl.build(user);
	}


}
