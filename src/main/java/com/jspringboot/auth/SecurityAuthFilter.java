package com.jspringboot.auth;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import com.jspringboot.auth.config.UserService;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
public class SecurityAuthFilter extends OncePerRequestFilter {

	@Autowired
	private JWTTokenService jwtTokenService;

	@Autowired
	private UserService userService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// Get Authorization- parameter values from request
		String token = request.getHeader("Authorization");
		// check if token start with Bearer
		if (token != null && token.startsWith("Bearer")) {
			// get another string by removing fist 7 character of 'Bearer' from token
			token = token.substring(7);
			try {
				// get user name from given token
				String userName = jwtTokenService.extractUsername(token);
				// check if is user authenticated and already present in security context
				if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
					// if user is not authenticated previously then pull user information
					UserDetails userDetails = userService.loadUserByUsername(userName);
					// Validate token user and fetched user is same an has valid expiration
					if (jwtTokenService.validateToken(token, userDetails)) {
						// Create auth object so can be set into security token again
						UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
								userDetails, null, userDetails.getAuthorities());
						authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
						// set details for token
						SecurityContextHolder.getContext().setAuthentication(authenticationToken);
					}
				}
			} catch (ExpiredJwtException e) {
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				return;
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		filterChain.doFilter(request, response);
	}

}
