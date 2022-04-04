package com.eazybytes.springsecuritybasic.controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import com.eazybytes.springsecuritybasic.model.User;

@RestController
public class OauthClientCredentialsController {
	
	@Autowired
    private OAuth2AuthorizedClientManager authorizedClientManager;
	
	@Autowired
	@Qualifier("eazyBankClient")
	private WebClient webClient;
	
	
	/**
	 * ESTE CONTROLADOR USA LA AUTENTICACION VIA CLIENT CREDENTIALS CONFIGURADA EN application.properties 'eazybankapi' 
	 * La configuracion es super simple, mirar documento!
	 * @param authentication
	 * @return
	 */
	
	@GetMapping("/myRepo")
	public String getLoanDetails(Authentication authentication) {
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("eazybankapi")
				.principal("jccpApplication").build();

		 OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);
		 
		return "Repo details from DB "+authorizedClient.getAccessToken().getTokenValue();
	}
	
	@GetMapping("/ownUser")
	public User index(@RegisteredOAuth2AuthorizedClient("eazybankapi") OAuth2AuthorizedClient authorizedClient) {
	    String resourceUri = "http://localhost:8081/user";

	    User body = webClient
	            .get()
	            .uri(resourceUri)
	           // .attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient)) 
	            .retrieve()
	            .bodyToMono(User.class)
	            .block();

	    return body;
	}

}
