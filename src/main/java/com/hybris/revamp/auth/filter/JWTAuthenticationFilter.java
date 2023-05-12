package com.hybris.revamp.auth.filter;

import com.hybris.revamp.auth.infra.JWTService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * 比一般filter更早值型
 * 不是透過filterConfig註冊，所以要@Component
 * 會查詢db user，為了把驗證後的資料(Authentication)帶給Security的Context
 * 此後就可以以getContext快速的拿到requester的資料
 *
 */
@Slf4j
@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter
{
	@Autowired
	private JWTService jwtService;

	@Autowired
	private UserDetailsService userDetailsService;

	/**
	 * 取出Header Authorization欄位(e.g."Bear 12qww2q1")
	 * 取出token的payload中的username
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain) throws ServletException, IOException
	{
		String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (authHeader != null)
		{
			String accessToken = authHeader.replace("Bearer ", "");
			log.info("accessToken:{}", accessToken);

			Map<String, Object> claims = jwtService.parseToken(accessToken);
			log.info("claims:{}", claims);
			String username = (String) claims.get("username");
			log.info("username:{}", username);
			UserDetails userDetails = userDetailsService.loadUserByUsername(username);
			log.info("userDetails in db:{}", userDetails);

			// param(Object principal, Object credentials)
			Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
			//					不做授權
			//					new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}
		chain.doFilter(request, response);
	}
}
