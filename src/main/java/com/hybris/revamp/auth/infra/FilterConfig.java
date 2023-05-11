package com.hybris.revamp.auth.infra;

import com.hybris.revamp.auth.filter.LogApiFilter;
import com.hybris.revamp.auth.filter.LogProcessTimeFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class FilterConfig {

	@Bean
	public FilterRegistrationBean logApiFilter() {
		FilterRegistrationBean<LogApiFilter> bean = new FilterRegistrationBean<>();
		bean.setFilter(new LogApiFilter());
		bean.addUrlPatterns("/*");
		bean.setName("logApiFilter");
		// 執行順序
		bean.setOrder(0);

		return bean;
	}

	@Bean
	public FilterRegistrationBean logProcessTimeFilter() {
		FilterRegistrationBean<LogProcessTimeFilter> bean = new FilterRegistrationBean<>();
		bean.setFilter(new LogProcessTimeFilter());
		bean.addUrlPatterns("/*");
		bean.setName("logProcessTimeFilter");
		bean.setOrder(1);

		return bean;
	}
}
