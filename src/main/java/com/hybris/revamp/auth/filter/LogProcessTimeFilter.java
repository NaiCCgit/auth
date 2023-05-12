package com.hybris.revamp.auth.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class LogProcessTimeFilter extends OncePerRequestFilter
{

	/**
	 * 有request時先觸發doFilterInternal
	 * 此filter方法只是計算處理時間
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain) throws ServletException, IOException
	{
		long startTime = System.currentTimeMillis();
		// 將request送至controller拿回response
		chain.doFilter(request, response);
		long processTime = System.currentTimeMillis() - startTime;

		log.info("{} ms", processTime);
	}
}
