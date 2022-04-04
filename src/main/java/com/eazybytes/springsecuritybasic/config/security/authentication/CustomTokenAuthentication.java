package com.eazybytes.springsecuritybasic.config.security.authentication;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class CustomTokenAuthentication extends AbstractAuthenticationToken {
	
	private static final long serialVersionUID = 1L;

	private String credentials;
	
	private final UserDetails udetails;

	public CustomTokenAuthentication(UserDetails udetails, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.udetails = udetails;
		super.setAuthenticated(true); // must use super, as we override
	}
	
	public CustomTokenAuthentication (String jwtToken) {
		super(null);
		this.credentials = jwtToken;
		this.udetails = null;
		super.setAuthenticated(false); // must use super, as we override
	}

	@Override
	public Object getCredentials() {
		return credentials;
	}

	@Override
	public UserDetails getPrincipal() {
		return udetails;
	}

	
	
}
