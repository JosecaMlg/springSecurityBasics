package com.eazybytes.springsecuritybasic.config.security.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.eazybytes.springsecuritybasic.config.security.authentication.CustomTokenAuthentication;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

public class JWTValidatorTokenFilter extends OncePerRequestFilter {
	
	@Value("${jwt.secret.key}")
	private String secretKey;
	
	@Value("${jwt.header.name}")
	private String headerName;
	
	private final  AuthenticationManager authManager;
	
	public JWTValidatorTokenFilter (AuthenticationManager authManager) {
		this.authManager = authManager;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String token = request.getHeader(headerName);
		if (StringUtils.hasText(token) && !token.contains("Bearer")){//token de oauth Bearer
			/** Forma HABITUAL
			try { ‡
				validateTokenAndSetAuth(token);
			} catch (Exception exp) {
				throw new BadCredentialsException("Token invalido");
			} */
			//Forma de prueba... usando auth manager y CustomJwtTokenAuthenticationProvider
			try {
				Authentication auth = authManager.authenticate(new CustomTokenAuthentication(token));
				SecurityContextHolder.getContext().setAuthentication(auth);
			} catch (AuthenticationException e) {
				//poner logger aqui
				enviaExceptionFrontal(e, response);
				return;
			}
		}
		
		filterChain.doFilter(request, response);
	}

	private void enviaExceptionFrontal(AuthenticationException e, HttpServletResponse response) throws IOException {
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.getWriter().write("Error Authenticacion, token invalido");
		response.flushBuffer();
	}

	private void validateTokenAndSetAuth(String token) {
		SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
		Claims claims = Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(token)
				.getBody();
		
		//Aqui habria que gestionar todas las excepciones para no devolver excepciones no controladas como 
		//ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException
		 
		String username =  (String) claims.get("username");
		String authorities =  (String) claims.get("authorities");
		
		Authentication auth  = new UsernamePasswordAuthenticationToken(username, null, AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
		SecurityContextHolder.getContext().setAuthentication(auth);
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		return request.getRequestURI().equals("/user");
	}
	
}
