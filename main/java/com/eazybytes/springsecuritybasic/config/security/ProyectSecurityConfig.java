package com.eazybytes.springsecuritybasic.config.security;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.reactive.function.client.WebClient;

import com.eazybytes.springsecuritybasic.config.authorization.CustomAuthorityVoter;
import com.eazybytes.springsecuritybasic.config.authorization.CustomRoleVoter;
import com.eazybytes.springsecuritybasic.config.checker.PostAuthenticationChecker;
import com.eazybytes.springsecuritybasic.config.security.authentication.CustomAccessDeniedHandler;
import com.eazybytes.springsecuritybasic.config.security.authentication.CustomAuthenticationEntryPoint;
import com.eazybytes.springsecuritybasic.config.security.filter.JWTTokenGeneratorFilter;
import com.eazybytes.springsecuritybasic.config.security.filter.JWTValidatorTokenFilter;
import com.eazybytes.springsecuritybasic.config.security.oauth.client.OAuth2AuthCustomRequestTokenConverter;
import com.eazybytes.springsecuritybasic.config.security.provider.CustomUserDetailsAuthenticationProvider;
import com.eazybytes.springsecuritybasic.config.security.userdetails.CustomUserDetailsService;
import com.eazybytes.springsecuritybasic.config.security.userdetails.CustomUserDetailsService2;

@Configuration
@EnableWebSecurity(debug=true)
public class ProyectSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	@Qualifier("customUserPwdAuthenticationProvider")
	AuthenticationProvider customPwdProvider;
	
	@Autowired
	@Qualifier("customJwtTokenAuthenticationProvider")
	AuthenticationProvider customJwtTokenAuthProvider;
	
	private static final String [] PUBLIC_URL = new String [] {"/notices", "/contact", "/login"};
	
	//Oauth2 keycloak configuration
	//@Override
	protected void configureOAUTH(HttpSecurity http) throws Exception{
		
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloackRoleConverter());
		
		http
		//Crosssiting
		.cors().configurationSource(corsConfig()).and()
		.anonymous().disable()
		//Si es una aplicacion expuesta en intranet podemos desactivarlo. Si no configurar
		//Previene ataques mediante links en emails o similar.
		//.csrf().ignoringAntMatchers(PUBLIC_URL).csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
		.csrf().disable()
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
		.authorizeRequests()
		// probar custom role & authority
		//.accessDecisionManager(accessDecisionManager())
			.antMatchers(PUBLIC_URL).permitAll()
			.antMatchers("/myBalance").hasAnyRole("ADMIN")
			.anyRequest().authenticated()
			.and()
		//si no se establece nada envia los errores automaticos definidos por SPRING, si ponemos
		// un CUSTOMAUTHENTRYPOINT nosotros definimos los mensajes de error genericos cuando 
		//se trata de acceder a un recurso sin autenticar
		.exceptionHandling().authenticationEntryPoint(new CustomAuthenticationEntryPoint())
		//Lo mismo que el de arriba pero para customizar los errores 403
		.accessDeniedHandler(new CustomAccessDeniedHandler())
		.and()
		.oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthenticationConverter);	
		}	
	//fin OAUTH2
	
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloackRoleConverter());
		configureOAuthClient(http);
		http
		//Crosssiting
		.cors().configurationSource(corsConfig()).and()
		.anonymous().disable()
		//Si es una aplicacion expuesta en intranet podemos desactivarlo. Si no configurar
		//Previene ataques mediante links en emails o similar.
		//.csrf().ignoringAntMatchers(PUBLIC_URL).csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
		.csrf().disable()
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
		.authorizeRequests()
		// probar custom role & authority
		//.accessDecisionManager(accessDecisionManager())
			.antMatchers(PUBLIC_URL).permitAll()
			.antMatchers("/myBalance").hasAnyAuthority("ADMIN")
			.anyRequest().authenticated()
			.and()
		.addFilterBefore(getTokenValidatorFilter(), BasicAuthenticationFilter.class)
		.addFilterAfter(getTokenFilter(), BasicAuthenticationFilter.class)
		//si no se establece nada envia los errores automaticos definidos por SPRING, si ponemos
		// un CUSTOMAUTHENTRYPOINT nosotros definimos los mensajes de error genericos cuando 
		//se trata de acceder a un recurso sin autenticar
		.exceptionHandling().authenticationEntryPoint(new CustomAuthenticationEntryPoint())
		//Lo mismo que el de arriba pero para customizar los errores 403
		.accessDeniedHandler(new CustomAccessDeniedHandler())
		.and()
		.formLogin().and()
		.httpBasic()
		.and()
		//configure login with OAUTH
		.oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthenticationConverter);
	}
	
	
	//Add simple filter
	//No es necesario DECLARAR este filtro puesto que se configura automaticamente en el metodo configureOAuthClient() de esta clase.
//	@Bean
//	public FilterRegistrationBean<OAuth2AuthorizationRequestRedirectFilter> loggingFilter(
//			ClientRegistrationRepository clientRegistrationRepo,
//			OAuth2AuthorizedClientService authorizedClientService){
//		
//	    FilterRegistrationBean<OAuth2AuthorizationRequestRedirectFilter> registrationBean 
//	      = new FilterRegistrationBean<>();
//	        
//	    registrationBean.setFilter(new OAuth2AuthorizationRequestRedirectFilter(clientRegistrationRepo));
//	    registrationBean.addUrlPatterns("/*");
//	    registrationBean.setOrder(2);
//	        
//	    return registrationBean;    
//	}
//	
//	@Bean
//	public FilterRegistrationBean<OAuth2AuthorizationCodeGrantFilter> loggingCodeFilter(
//			ClientRegistrationRepository clientRegistrationRepo,
//			OAuth2AuthorizedClientRepository authorizedClientRepository,
//			AuthenticationManager authenticationManager){
//		
//	    FilterRegistrationBean<OAuth2AuthorizationCodeGrantFilter> registrationBean 
//	      = new FilterRegistrationBean<>();
//	        
//	    registrationBean.setFilter(new OAuth2AuthorizationCodeGrantFilter(clientRegistrationRepo, authorizedClientRepository, authenticationManager));
//	    registrationBean.addUrlPatterns("/login/oauth2/code/*");
//	    registrationBean.setOrder(3);
//	    
//	    return registrationBean;    
//	}
	
	
	private HttpSecurity configureOAuthClient(HttpSecurity http) throws Exception {
		http.oauth2Client()
			.authorizationCodeGrant();
		return http;
	}
	
	@Bean 
	public DefaultAuthorizationCodeTokenResponseClient customizeAccesTokenRequest() {
		DefaultAuthorizationCodeTokenResponseClient token = new DefaultAuthorizationCodeTokenResponseClient();
		token.setRequestEntityConverter(new OAuth2AuthCustomRequestTokenConverter());
		return token;
	}
	
	@Bean
	public OAuth2AuthorizedClientManager authorizedClientManager(
	        ClientRegistrationRepository clientRegistrationRepository,
	        OAuth2AuthorizedClientRepository authorizedClientRepository) {

	    OAuth2AuthorizedClientProvider authorizedClientProvider =
	            OAuth2AuthorizedClientProviderBuilder.builder()
	                    .clientCredentials()
	                    .authorizationCode()
	                    .refreshToken()
	                    .build();

	    DefaultOAuth2AuthorizedClientManager authorizedClientManager =
	            new DefaultOAuth2AuthorizedClientManager(
	                    clientRegistrationRepository, authorizedClientRepository);
	    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
	    
	    return authorizedClientManager;
	}
	
	@Bean("eazyBankClient")
	WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
	    ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
	            new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
	    
	    oauth2Client.setDefaultClientRegistrationId("eazybankapi");
	    return WebClient.builder()
	            .apply(oauth2Client.oauth2Configuration())
	            .build();
	}
	
	@Bean("eazyBankAuthorizationCodeFlow")
	WebClient webClientAuthCode(OAuth2AuthorizedClientManager authorizedClientManager) {
	    ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
	            new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
	    
	    oauth2Client.setDefaultClientRegistrationId("eazyuiclient");
	    return WebClient.builder()
	            .apply(oauth2Client.oauth2Configuration())
	            .build();
	}
	
	//para definir si se puede acceder o no customizado dependiendo de rol y algo mas...
	@Bean
	public AccessDecisionManager accessDecisionManager() {
	    List<AccessDecisionVoter<? extends Object>> decisionVoters 
	      = Arrays.asList(
	        new CustomRoleVoter(),
	        new CustomAuthorityVoter());
	    return new UnanimousBased(decisionVoters);
	}
	
	//probar suwitch user
	// probar authenticacion

	/** IN MEMORY AUTH **/
	
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception{
//		auth.inMemoryAuthentication()
//			.withUser("admin")
//			.password("1234")
//			.authorities("ADMIN", "ADMIN2")
//		.and()
//			.withUser("user")
//			.password("1234")
//			.authorities("RREAD")
//		.and()// siempre pasar un password ecoder!!
//			.passwordEncoder(NoOpPasswordEncoder.getInstance());
//		
//	}
	
/** With UserDetailsManager */
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception{
//		InMemoryUserDetailsManager udservice = new InMemoryUserDetailsManager();
//		UserDetails user = User.withUsername("ADMIN").password("1234").authorities("ADMIN").build();
//		UserDetails user1 = User.withUsername("USER").password("1234").authorities("USER").build();
//		
//		udservice.createUser(user);
//		udservice.createUser(user1);
//		
//		auth.userDetailsService(udservice);
//		
//	}
	// CORS CONFIGURATION SIRVE PARA HABILITAR EN LOS NAVEGADORES PETICIONES DESDE DISTINTOS DOMINIOS
	public CorsConfigurationSource corsConfig() {
		return  new CorsConfigurationSource() {
			
			@Override
			public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
				CorsConfiguration config =  new CorsConfiguration();
				//que dominios (host) estan autorizados
				config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
				//HTTP METHODS ALOWED * MEANS EVERYONES
				config.setAllowedMethods(Collections.singletonList("*"));
				//ALLOW AUTHENTICATE
				config.setAllowCredentials(true);
				//cabeceras aceptadas, * todas
				config.setAllowedHeaders(Collections.singletonList("*"));
				//OPCIONAL! SI SE USA TOKEN , SE INDICA A LOS FRONTALES QUE HEADER ES NECESARIO.
				//ES COMPLETAMENTE OPCIONAL
				config.setExposedHeaders(Collections.singletonList("Authorization"));
				//AMOUNT OF TIME WHICH THE BROWSER WILL CATCH THIS CONFIGURATION
				config.setMaxAge(Duration.ofHours(24));
				
				return config;
			}
		};
	}
	
	//FIN CORSCONFIGURATION
	
	
	//bean Filtros de token jwt
	@Bean
	public JWTTokenGeneratorFilter getTokenFilter() {
		return new JWTTokenGeneratorFilter();
	}
	
	@Bean
	public JWTValidatorTokenFilter getTokenValidatorFilter() throws Exception {
		return new JWTValidatorTokenFilter(authenticationManager());
	}
	
// CUSTOM Udetails
	
	@Override 
	protected void configure (AuthenticationManagerBuilder auth)  throws Exception {
		auth
		//.userDetailsService(getUDService())
		//.and()
		//Optional configure authProvider
		.authenticationProvider(getAuthProvider())
		.authenticationProvider(getAuthProvider2())
		.authenticationProvider(customPwdProvider)
		.authenticationProvider(customJwtTokenAuthProvider);
	}
	
	@Bean
	public UserDetailsService getUDService() {
		return new CustomUserDetailsService();
	}
	
	@Bean
	public UserDetailsService getUDService2() {
		return new CustomUserDetailsService2();
	}
	
	
	
	@Bean
	public CustomUserDetailsAuthenticationProvider getAuthProvider() {
		CustomUserDetailsAuthenticationProvider cap = new CustomUserDetailsAuthenticationProvider(getUDService());
		cap.setPasswordEncoder(passwordEncoder());
		// checkear cualquier cosa del usuario a posteriori
		cap.setPostAuthenticationChecks(new PostAuthenticationChecker());
		return cap;
	}
	
	@Bean
	public CustomUserDetailsAuthenticationProvider getAuthProvider2() {
		CustomUserDetailsAuthenticationProvider cap = new CustomUserDetailsAuthenticationProvider(getUDService2());
		cap.setPasswordEncoder(passwordEncoder2());
		return cap;
	}
	
// FIN DE CUSTOM USER DETAILS	

	@Bean("bycriptPswEncoder")
	public PasswordEncoder passwordEncoder2() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
}



