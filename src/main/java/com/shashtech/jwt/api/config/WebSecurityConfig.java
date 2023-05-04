package com.shashtech.jwt.api.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.shashtech.jwt.api.filter.JwtFilter;
import com.shashtech.jwt.api.service.CustomUserDetailsService;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class WebSecurityConfig {

	@Autowired
	CustomUserDetailsService customUserDetailsService;

	@Bean
	public JwtFilter authTokenFilter() {
		return new JwtFilter();
	}

	@Bean
	public PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setUserDetailsService(customUserDetailsService);
		daoAuthenticationProvider.setPasswordEncoder(encoder());
		return daoAuthenticationProvider;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
		return authConfig.getAuthenticationManager();
	}
	
	@Bean
	public SecurityFilterChain chain(HttpSecurity httpSecurity)throws Exception {
		httpSecurity.cors().and().csrf().disable()
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and()
		.authorizeRequests()
		//.antMatchers("/api/auth/signup").permitAll()
		.antMatchers("/api/auth/**").permitAll()
		.antMatchers("/api/test/all").permitAll()
		.anyRequest().authenticated();
		
		httpSecurity.authenticationProvider(authenticationProvider());
		httpSecurity.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);
		return httpSecurity.build();
	}
}
