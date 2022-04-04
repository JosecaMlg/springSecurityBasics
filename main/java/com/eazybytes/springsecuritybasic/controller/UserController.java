package com.eazybytes.springsecuritybasic.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.eazybytes.springsecuritybasic.model.User;

@RestController
public class UserController {
	
	@GetMapping("/user")
	public User getCardsDetails(Authentication authentication) {
		User usuario =  new User();
		if (authentication instanceof JwtAuthenticationToken) {
			usuario = mapUserFromJwt((JwtAuthenticationToken) authentication);
		}
		else if (authentication.getPrincipal() instanceof UserDetails) {
			usuario = mapUserFromUdetails((UserDetails) authentication.getPrincipal());
		}
		return usuario;
	}

	private User mapUserFromUdetails(UserDetails ud) {
		User usuario =  new User();
		usuario.setAuthStatus("Authenticated");
		usuario.setEmail(ud.getUsername());
		usuario.setMobileNumber("666666666");
		usuario.setName(ud.getUsername());
		usuario.setNumber(1);
		usuario.setPassword(ud.getPassword());
		usuario.setRole(ud.getAuthorities().toString());
		usuario.setStatusMsg("Active");
		return usuario;
	}

	private User mapUserFromJwt(JwtAuthenticationToken authentication) {
		User usuario =  new User();
		usuario.setAuthStatus("Authenticated");
		usuario.setEmail(authentication.getName());
		usuario.setMobileNumber("666666666");
		usuario.setName(authentication.getName());
		usuario.setNumber(1);
		usuario.setPassword(authentication.getToken().getTokenValue());
		usuario.setRole(authentication.getAuthorities().toString());
		usuario.setStatusMsg("Active");
		return usuario;
	}
}
