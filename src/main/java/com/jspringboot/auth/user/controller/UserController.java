package com.jspringboot.auth.user.controller;

import java.nio.file.attribute.UserPrincipalNotFoundException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jspringboot.auth.AuthRequest;
import com.jspringboot.auth.JWTTokenService;
import com.jspringboot.auth.user.entity.UserEntity;
import com.jspringboot.auth.user.repository.UserRepository;

@RestController
@RequestMapping(value = "/user")
public class UserController {
	@Autowired
	UserRepository userRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JWTTokenService tokenService;

	@Autowired
	AuthenticationManager authenticationManager;

	@PostMapping("/register")
	public String addProduct(@RequestBody UserEntity entity) {
		try {
			entity.setPassword(encoder.encode(entity.getPassword()));
			userRepository.save(entity);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "User added successfully";
	}

	@PostMapping("/token")
	public String getToken(@RequestBody AuthRequest authRequest) throws UserPrincipalNotFoundException {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(authRequest.getUserName(), authRequest.getPassword()));
		if (authentication.isAuthenticated()) {
			return tokenService.generateToken(authRequest.getUserName());
		} else {
			throw new UserPrincipalNotFoundException("Unauthorized user");
		}

	}
}
