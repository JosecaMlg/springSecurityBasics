package com.eazybytes.springsecuritybasic.config.security.provider;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component("customUserPwdAuthenticationProvider")
public class CustomUserPwdAuthenticationProvider implements AuthenticationProvider {

	private List<UserDetails> USER_STORAGE = Arrays.asList(new UserDetails[]{
			//pasword 1234 bycrypt 10 rounds
			User.withUsername("user5@jc.com").password("$2a$10$XFT64KO5gq6h5v05Ogv4NulQRNQ52FVF/1V/bPZmErOIQ8Jnr6oY6").authorities("USER").build(),
			User.withUsername("user6@jc.com").password("$2a$10$XFT64KO5gq6h5v05Ogv4NulQRNQ52FVF/1V/bPZmErOIQ8Jnr6oY6").authorities("USER").build()
			});
	
	
	@Qualifier("bycriptPswEncoder")
	@Autowired
	PasswordEncoder bycriptPwdEncoder;
	
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		Assert.isAssignable(authentication.getClass(), UsernamePasswordAuthenticationToken.class, String.format("Authentication must be UsernamePasswordAuthenticationToken but were found %s",authentication.getClass().getName()));
		
		UsernamePasswordAuthenticationToken auth = (UsernamePasswordAuthenticationToken) authentication;
		
		List<UserDetails> userMatch = USER_STORAGE.stream().filter(u -> u.getUsername().equals(auth.getName())).collect(Collectors.toList());
		
		if (userMatch.size() == 1) { // user found authenticate!
			return createAuthFromUser(userMatch.get(0), auth);
		}
		else if (userMatch.isEmpty()) {
			throw new BadCredentialsException("User not found! "+auth.getName());
		}
		else {
			throw new InsufficientAuthenticationException("Insufficient Authentication TOO MANY RESULTS! -> "+userMatch);
		}
	}

	private Authentication createAuthFromUser(UserDetails userDetails, UsernamePasswordAuthenticationToken auth) {
		
		//Check security
		if (bycriptPwdEncoder.matches((CharSequence) auth.getCredentials(), userDetails.getPassword())) {
			return new UsernamePasswordAuthenticationToken(userDetails.getUsername(), auth.getCredentials(), userDetails.getAuthorities());
		}
		else {
			throw new BadCredentialsException("Incorrect password!");
		}
		
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
	}

}

