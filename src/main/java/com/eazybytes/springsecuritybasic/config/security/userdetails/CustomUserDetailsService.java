package com.eazybytes.springsecuritybasic.config.security.userdetails;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CustomUserDetailsService implements UserDetailsService {

	private List<UserDetails> USER_STORAGE = Arrays.asList(new UserDetails[]{
			User.withUsername("admin@jc.com").password("12345").authorities("ADMIN").build(),
			User.withUsername("user@jc.com" ).password("12345").authorities("USER").build()
			});
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Objects.requireNonNull(username, "Username cannot be null!");
		List<UserDetails> userFiltered = USER_STORAGE.stream().filter(e -> username.equals(e.getUsername())).collect(Collectors.toList());
		
		if (userFiltered.size() > 1) {
			throw new RuntimeException(String.format("Too many results in loadUserByUsername. There are more than 1 user with the name %s", username));
		}
		else if (userFiltered.size() == 0) {
			throw new UsernameNotFoundException(String.format("There is no user with the username %s in the database", username));
		}
		
		UserDetails udSelected = userFiltered.get(0);
		
		//super importante no devolver el objeto original de ninguna cache o similar puesto que es MUTABLE!
		return new User(udSelected.getUsername(), udSelected.getPassword(), udSelected.isEnabled(), udSelected.isAccountNonExpired(),
				udSelected.isCredentialsNonExpired(), udSelected.isAccountNonLocked(), udSelected.getAuthorities());
	}

}
