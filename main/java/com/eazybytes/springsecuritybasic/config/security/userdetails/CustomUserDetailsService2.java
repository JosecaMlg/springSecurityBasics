package com.eazybytes.springsecuritybasic.config.security.userdetails;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CustomUserDetailsService2 implements UserDetailsService {

	private List<UserDetails> USER_STORAGE = Arrays.asList(new UserDetails[]{
			//pasword 1234 bycrypt 10 rounds
			User.withUsername("user3@jc.com").password("$2a$12$pNCht842CQv7zWpfxKLBsuUH1.DqL6LZBwZT06cHtZ8o.nSUu9lnS").roles("USER").authorities("READ").build(),
			User.withUsername("user4@jc.com").password("$2a$12$pNCht842CQv7zWpfxKLBsuUH1.DqL6LZBwZT06cHtZ8o.nSUu9lnS").roles("USER").authorities("READ","WRITE").build()
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
