package com.eazybytes.springsecuritybasic.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CardsController {
	
	@GetMapping("/myCards")
	//@PreAuthorize("hasRole('ADMIN')")
	@PreAuthorize("hasAuthority('ADMIN')")
	public String getCardsDetails(Authentication authentication) {
		return "Cards details from DB";
	}
}