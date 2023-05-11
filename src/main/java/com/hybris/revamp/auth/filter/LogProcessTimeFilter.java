package com.hybris.revamp.auth.filter;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class LogProcessTimeFilter extends OncePerRequestFilter
{

	/**
	 * 有request時先觸發doFilterInternal
	 *
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain) throws ServletException, IOException
	{
		long startTime = System.currentTimeMillis();
		// 將request送至controller拿回response
		chain.doFilter(request, response);
		long processTime = System.currentTimeMillis() - startTime;

		System.out.println(processTime + " ms");
	}
}
