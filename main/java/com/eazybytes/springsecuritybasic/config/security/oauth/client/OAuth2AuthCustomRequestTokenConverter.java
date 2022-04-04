package com.eazybytes.springsecuritybasic.config.security.oauth.client;

import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

public class OAuth2AuthCustomRequestTokenConverter extends OAuth2AuthorizationCodeGrantRequestEntityConverter {

	@Override
	protected MultiValueMap<String, String> createParameters(
			OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) {
		ClientRegistration clientRegistration = authorizationCodeGrantRequest.getClientRegistration();
		OAuth2AuthorizationExchange authorizationExchange = authorizationCodeGrantRequest.getAuthorizationExchange();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add(OAuth2ParameterNames.GRANT_TYPE, authorizationCodeGrantRequest.getGrantType().getValue());
		parameters.add(OAuth2ParameterNames.CODE, authorizationExchange.getAuthorizationResponse().getCode());
		String redirectUri = authorizationExchange.getAuthorizationRequest().getRedirectUri();
		String codeVerifier = authorizationExchange.getAuthorizationRequest()
				.getAttribute(PkceParameterNames.CODE_VERIFIER);
		if (redirectUri != null) {
			parameters.add(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
		}
		if (!ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(clientRegistration.getClientAuthenticationMethod())
				&& !ClientAuthenticationMethod.BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
			parameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
		}
		if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(clientRegistration.getClientAuthenticationMethod())
				|| ClientAuthenticationMethod.POST.equals(clientRegistration.getClientAuthenticationMethod())) {
			parameters.add(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
		}
		if (codeVerifier != null) {
			parameters.add(PkceParameterNames.CODE_VERIFIER, codeVerifier);
		}
		return parameters;
	}

	
}
