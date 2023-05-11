package com.hybris.revamp.auth.infra;

import com.hybris.revamp.auth.filter.JWTAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


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
	 *  /auth/user POST 是建立使用者 允許
	 *  swagger, h2 允許
	 *  其餘所有 API，需要驗證
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
//				.antMatchers(HttpMethod.POST, "/auth/**").permitAll()
//				.antMatchers(HttpMethod.POST, "/auth/user").permitAll()
//				.antMatchers("/h2-console/**").permitAll()
//				.antMatchers("/swagger-ui/**").permitAll()
				.antMatchers("/**").permitAll()
				.anyRequest().authenticated()
				.and()
//				.addFilterBefore((javax.servlet.Filter)jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
//				.sessionManagement()
//				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//				.and()
				// 為h2關上CSRF防護
//				.csrf().ignoringAntMatchers("/h2-console/**")
//				.and().headers().frameOptions().sameOrigin();
				// 關閉CSRF防護,允許Postman與前端request
				.csrf().disable()
				// 開啟前端spring預設畫面
				.formLogin();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
				.userDetailsService(userDetailsService)
				.passwordEncoder(new BCryptPasswordEncoder());
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
