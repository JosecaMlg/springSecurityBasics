package com.eazybytes.springsecuritybasic.config.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public class KeycloackRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

	@Override
	public Collection<GrantedAuthority> convert(Jwt value) {
		Map<String, Object> realAccess = (Map<String, Object>) value.getClaims().get("realm_access");
		
		if (realAccess == null || realAccess.isEmpty()) {
			return new ArrayList<>();
		}
		
		Collection<GrantedAuthority> returnVal = ((List<String>) realAccess.get("roles"))
				.stream()
				.map(rol -> "ROLE_"+rol)
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());
		
		return returnVal;
	}

}
