package com.eazybytes.springsecuritybasic.config.checker;

import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;

public class PostAuthenticationChecker implements UserDetailsChecker {

	@Override
	public void check(UserDetails user) {
		if (!user.isCredentialsNonExpired()) {
			throw new CredentialsExpiredException("User credentials have expired");
		}

	}

}
