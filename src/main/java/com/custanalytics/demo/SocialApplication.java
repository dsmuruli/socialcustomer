package com.custanalytics.demo;

import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

@SpringBootApplication
@EnableOAuth2Sso
@RestController
public class SocialApplication extends WebSecurityConfigurerAdapter {

	@Autowired
	OAuth2RestTemplate facebookTemplate;

	public static void main(String[] args) {
		System.out.println("Started social customer application");
		SpringApplication.run(SocialApplication.class, args);
	}

	@RequestMapping("/user")
	public Principal user(Principal principal) {
		System.out.println("We have just entered the user endpoint");
		return principal;
	}

	@RequestMapping("/facebookApiTest")
	public String facebookApiTests() {
		System.out.println("We have just entered the user facebook api test");
		String result = "5";
		result = "The Access Token from the template is is: "
				+ facebookTemplate.getOAuth2ClientContext().getAccessToken()
						.getValue();
		return result;
	}

	@RequestMapping("/getCurrentUserInfo")
	public String getCurrentUserInfo() {
		String userInfo = "Default Info";
		// curl -i -X GET \
		// "https://graph.facebook.com/v2.6/1220198547991744?access_token=EAACEdEose0cBAEpsmuqNaecIExTgUZAViNsn7LV1Rc2rN1TUgYSHhMXZBSUhCO6z303KEcp6EG6hInggYZAPZB8XAZCYPgA0umyXvaZBE60B2FBg3OCUe7dfRmRxJZAZBefQik6ZC02b4UlZAZCLRU2l9kI1bG0CQTJeoOlBEnT8nJKlgZDZD"
		String currentUserUrl = "https://graph.facebook.com/v2.6/me";
		String accessToken = facebookTemplate.getOAuth2ClientContext()
				.getAccessToken().getValue();
		Map<String, String> vars = new HashMap<String, String>();
		vars.put("access_token", accessToken);
		vars.put("access_token", facebookTemplate.getOAuth2ClientContext()
				.getAccessToken().getValue());

		ResponseEntity<String> response = facebookTemplate.exchange(
				currentUserUrl, HttpMethod.GET, null, String.class);

		return response.getBody();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.antMatcher("/**").authorizeRequests()
				.antMatchers("/", "/login**", "/webjars/**").permitAll()
				.anyRequest().authenticated().and().logout()
				.logoutSuccessUrl("/").permitAll().and().csrf()
				.csrfTokenRepository(csrfTokenRepository()).and()
				.addFilterAfter(csrfHeaderFilter(), CsrfFilter.class);
	}

	private Filter csrfHeaderFilter() {
		return new OncePerRequestFilter() {
			@Override
			protected void doFilterInternal(HttpServletRequest request,
					HttpServletResponse response, FilterChain filterChain)
					throws ServletException, IOException {
				CsrfToken csrf = (CsrfToken) request
						.getAttribute(CsrfToken.class.getName());
				if (csrf != null) {
					Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
					String token = csrf.getToken();
					if (cookie == null || token != null
							&& !token.equals(cookie.getValue())) {
						System.out.println("The facebook token is : " + token);
						cookie = new Cookie("XSRF-TOKEN", token);
						cookie.setPath("/");
						response.addCookie(cookie);
					}
				}
				filterChain.doFilter(request, response);
			}
		};
	}

	private CsrfTokenRepository csrfTokenRepository() {
		HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
		repository.setHeaderName("X-XSRF-TOKEN");
		return repository;
	}

}
