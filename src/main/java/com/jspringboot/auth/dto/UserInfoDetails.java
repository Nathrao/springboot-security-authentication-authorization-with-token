package com.jspringboot.auth.dto;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.jspringboot.auth.user.entity.UserEntity;

public class UserInfoDetails implements UserDetails {

	String name;
	List<GrantedAuthority> role;
	String password;

	public UserInfoDetails(UserEntity entity) {
		super();
		this.name = entity.getName();
		this.role = Arrays.stream(entity.getRole().split(",")).map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());
		this.password = entity.getPassword();
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return role;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return name;
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

}
