package com.eazybytes.springsecuritybasic.controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import com.eazybytes.springsecuritybasic.model.User;

@RestController
public class OauthAuthCodeController {
	
	@Autowired
    private OAuth2AuthorizedClientManager authorizedClientManager;
	
	@Autowired
	@Qualifier("eazyBankAuthorizationCodeFlow")
	private WebClient webClient;
	
	
	
	@GetMapping("/authRequest")
	public String getLoanDetails(Authentication authentication) {
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("eazyuiclient")
				.principal(authentication.getName()).build();

		 OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);
		 
		return "Repo details from DB "+authorizedClient.getAccessToken().getTokenValue();
	}
	
	@GetMapping("/ownUser2")
	public User index(@RegisteredOAuth2AuthorizedClient("eazyuiclient") OAuth2AuthorizedClient authorizedClient) {
	    String resourceUri = "http://localhost:8081/user";

	    User body = webClient
	            .get()
	            .uri(resourceUri)
	            //.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient)) 
	            .retrieve()
	            .bodyToMono(User.class)
	            .block();

	    return body;
	}

}
