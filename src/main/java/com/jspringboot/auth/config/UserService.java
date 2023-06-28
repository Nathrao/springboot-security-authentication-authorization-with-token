package com.jspringboot.auth.config;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import com.jspringboot.auth.dto.UserInfoDetails;
import com.jspringboot.auth.user.entity.UserEntity;
import com.jspringboot.auth.user.repository.UserRepository;

@Component
public class UserService implements UserDetailsService {

	@Autowired
	private UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<UserEntity> userOptional = userRepository.findByName(username);
		return userOptional.map(UserInfoDetails::new).orElseThrow(() -> new UsernameNotFoundException("userNot found"));
	}


}
