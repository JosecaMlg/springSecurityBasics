package com.eazybytes.springsecuritybasic.config.security.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		System.out.println("An access Denied exception has ocurrred "+accessDeniedException.getMessage());
		response.setStatus(403);
		response.getWriter().write("An error has ocurred with the authorization :: "+accessDeniedException.getClass().getSimpleName());
		response.flushBuffer();
		
	}

}
