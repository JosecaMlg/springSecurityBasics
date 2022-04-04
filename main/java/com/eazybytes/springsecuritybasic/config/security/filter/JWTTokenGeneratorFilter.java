package com.eazybytes.springsecuritybasic.config.security.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

public class JWTTokenGeneratorFilter extends OncePerRequestFilter {

	@Value("${jwt.secret.key}")
	String secretKey;
	
	@Value("${jwt.header.name}")
	String headerName;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();

		if (auth != null) { //Existe usuario autenticado, generamos token
			SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
			String jwtToken = Jwts.builder()
				.setIssuer("Eazy Bank")
				.setSubject("JWT Token")
				.claim("username", auth.getName())
				.claim("authorities", populateAuthorities(auth.getAuthorities()))
				.setIssuedAt(new Date())
				.setExpiration(new Date(Instant.now().plus(Duration.ofMinutes(10)).toEpochMilli()))
				.signWith(key)
				.compact();
			
			response.setHeader(headerName, jwtToken);	
		}
		
		filterChain.doFilter(request, response);
	}
	
	@Override
	protected boolean shouldNotFilter(HttpServletRequest srequest) {
		return !srequest.getServletPath().equals("/user");
	}
	
	private String populateAuthorities(Collection<? extends GrantedAuthority> authorities) {
		Set<String> result = authorities
				.stream().map(e -> e.getAuthority())
				.collect(Collectors.toSet());
		
		return String.join(",", result);
	}
	
}
