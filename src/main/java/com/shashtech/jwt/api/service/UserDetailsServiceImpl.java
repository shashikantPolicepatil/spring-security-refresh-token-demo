package com.shashtech.jwt.api.service;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.shashtech.jwt.api.entity.User;

public class UserDetailsServiceImpl implements UserDetails{

	/**
	 * 
	 */
	private static final long serialVersionUID = 623212371892444641L;
	
	private Integer id;
	private String userName;
	private String email;
	
	@JsonIgnore
	private String password;

	private Collection<? extends GrantedAuthority> authorities;
	
	public UserDetailsServiceImpl(Integer id,String userName,String email,String password,
			Collection<? extends GrantedAuthority> authorities) {
		this.id=id;
		this.userName=userName;
		this.email=email;
		this.password=password;
		this.authorities=authorities;
	}
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return userName;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public void setUsername(String userName) {
		this.userName = userName;
	}
	
	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		UserDetailsServiceImpl user = (UserDetailsServiceImpl) o;
		return Objects.equals(id, user.id);
	}
	
	public static UserDetails build(User user) {
		List<SimpleGrantedAuthority> authorities = user.getUserRoles().stream()
		.map(role-> new SimpleGrantedAuthority(role.getName().name()))
		.collect(Collectors.toList());
		return new UserDetailsServiceImpl(user.getId(), user.getUserName(),
				user.getEmail(), user.getPassword(), authorities);
	}
}
