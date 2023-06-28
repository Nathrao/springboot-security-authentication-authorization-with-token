package com.jspringboot.auth;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JWTTokenService {

	//HS256 SECRET KEY same as SignatureAlgorithm.HS256
	public static final String SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";

	public String generateToken(String username) {
		Map<String, Object> claims = new HashMap();
		return creatToken(claims, username);
	}

	/**
	 *   This method set expiration time as 2 minutes ,subject as userName,
	 *   token issue date,
	 *   token generator secret key and secret algorithm
	 */
	
	public String creatToken(Map<String, Object> claims, String username) {
		return Jwts.builder().setClaims(claims)
				.setExpiration(new Date(System.currentTimeMillis() + (1000 * 60 * 2)))
				.setSubject(username).setIssuedAt(new Date(System.currentTimeMillis()))
				.signWith(getSecrect(),  SignatureAlgorithm.HS256).compact();
	}

	//Create secret key
	private Key getSecrect() {
		byte[] secretKeyByte = Decoders.BASE64.decode(SECRET);
		return Keys.hmacShaKeyFor(secretKeyByte);
	}

	private Claims extractAllClaims(String token) {
		return Jwts.parserBuilder().setSigningKey(getSecrect()).build().parseClaimsJws(token).getBody();
	}

	private Boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = extractUsername(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}
}
