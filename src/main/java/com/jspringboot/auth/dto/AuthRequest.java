package com.jspringboot.auth.dto;

import lombok.Data;

@Data
public class AuthRequest {

	String userName;
	String password;
}
