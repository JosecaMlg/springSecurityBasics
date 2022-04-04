package com.eazybytes.springsecuritybasic.config.security.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		System.out.println("An auth exception has ocurrred "+authException);
		response.setStatus(401);
		response.getWriter().write("An error has ocurred with the authentication :: "+authException.getClass().getSimpleName());
		response.flushBuffer();
	}

}
