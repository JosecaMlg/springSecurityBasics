package com.eazybytes.springsecuritybasic.config.security.provider;

import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import com.eazybytes.springsecuritybasic.config.security.authentication.CustomTokenAuthentication;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component("customJwtTokenAuthenticationProvider")
public class CustomJwtTokenAuthenticationProvider implements AuthenticationProvider {

	@Value("${jwt.secret.key}")
	String secretKey;
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		Assert.isAssignable(authentication.getClass(), CustomTokenAuthentication.class, String.format("Authentication must be UsernamePasswordAuthenticationToken but were found %s",authentication.getClass().getName()));
		
		CustomTokenAuthentication auth = (CustomTokenAuthentication) authentication;
		
		Authentication finalAuth = null;
		
		if (StringUtils.hasText((String) auth.getCredentials())){
			try {
				finalAuth = getUserAutenticationFromToken((String) auth.getCredentials());
			} catch (Exception exc) {
				throw new BadCredentialsException("Incorrect jwtToken!");
			}
		}
		
		return finalAuth;
	}

	private CustomTokenAuthentication getUserAutenticationFromToken(String token) {
		
		SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
		Claims claims = Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(token)
				.getBody();
		
		//Aqui habria que gestionar todas las excepciones para no devolver excepciones no controladas como 
		//ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException
		 
		String username =  (String) claims.get("username");
		String authorities =  (String) claims.get("authorities");
		
		UserDetails user = User.withUsername(username).password("jwtToken").authorities(AuthorityUtils.commaSeparatedStringToAuthorityList(authorities)).build();
		
		return new CustomTokenAuthentication(user, AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));	
	}
	
	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.isAssignableFrom(CustomTokenAuthentication.class);
	}

}

