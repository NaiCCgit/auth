package com.hybris.revamp.auth.infra;

import com.hybris.revamp.auth.filter.JWTAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


/**
 *  @EnableWebSecurity 是一種 @Configuration
 *  可以override哪些url要讓 spring security 通過
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter
{

	@Autowired
	private JWTAuthenticationFilter jwtAuthenticationFilter;

	@Autowired
	private UserDetailsService userDetailsService;

	/**
	 *  /auth API 及其底下 允許
	 *  swagger, h2 允許
	 *  其餘所有 API，需要驗證
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
				.antMatchers(HttpMethod.POST, "/controlled").authenticated()
				.antMatchers(HttpMethod.GET).permitAll()
				.antMatchers(HttpMethod.POST, "/auth/**").permitAll()
//				.antMatchers(HttpMethod.POST, "/auth/user").permitAll()
				// 允許h2開頭的網址
				.antMatchers("/h2-console/**").permitAll()
//				.antMatchers(AUTH_WHITELIST).permitAll()
//				.antMatchers("/**").permitAll()
				.anyRequest().authenticated()
				.and()
				// 把我們自己做的filter放在原生filter的前面
				.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
				// 停用session
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				// 關閉CSRF防護,允許Postman與前端request
				.csrf().disable();

		// 因為h2後台有iframe，security default禁止，所以要設定開放
		http.headers().frameOptions().sameOrigin();
		// 為h2關上CSRF防護
		//				.csrf().ignoringAntMatchers("/h2-console/**")

				// 開啟前端spring預設畫面
//				.formLogin();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
				.userDetailsService(userDetailsService)
				.passwordEncoder(this.bCryptPasswordEncoder());
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	/**
	 * 需要AuthenticationManager幫助我們進行帳密驗證
	 * 以@Bean來建立出元件
	 */
	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

}
