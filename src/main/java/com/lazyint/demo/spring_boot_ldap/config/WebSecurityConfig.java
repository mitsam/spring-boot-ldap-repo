package com.lazyint.demo.spring_boot_ldap.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@SuppressWarnings("deprecation")
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	private static final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);

	@Value("${app.ldap.userdnpattern}")
	private String userDnPattern;

	@Value("${app.ldap.groupsearchbase}")
	private String groupSearchBase;

	@Value("${app.ldap.url}")
	private String ldapUrl;

	@Value("${app.ldap.userpasswordattribute}")
	private String passwordAtrribute;
	
	@Override
    public void configure(WebSecurity web) throws Exception {
		web.ignoring()
		.antMatchers("/css/**")
		.antMatchers("/js/**")
		.antMatchers("/webjars/**");
    }

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		.csrf().disable()
		.authorizeRequests()
			.anyRequest()
			.fullyAuthenticated()
			.and()
		.formLogin()
			.loginPage("/ldaplogin").permitAll().defaultSuccessUrl("/home")
			.and()
		.logout()
			.permitAll().logoutSuccessUrl("/ldaplogin?logout")
			.invalidateHttpSession(true);
	}

	@Bean
	WebMvcConfigurer myWebMvcConfigurer() {
		return new WebMvcConfigurerAdapter() {
			@Override
			public void addViewControllers(ViewControllerRegistry registry) {
				registry.addViewController("/ldaplogin").setViewName("ldaplogin");;
				registry.setOrder(Ordered.HIGHEST_PRECEDENCE);
			}
		};
	}

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		logger.debug("this.userDnPattern {}", this.userDnPattern);
		logger.debug("this.groupSearchBase {}", this.groupSearchBase);
		logger.debug("this.ldapUrl {}", this.ldapUrl);
		logger.debug("this.passwordAtrribute {}", this.passwordAtrribute);
		auth
		.ldapAuthentication()
		.userDnPatterns(this.userDnPattern)
		.groupSearchBase(this.groupSearchBase)
		.contextSource().url(this.ldapUrl)
		.and()
		.passwordCompare().passwordEncoder(new LdapShaPasswordEncoder())
		.passwordAttribute(this.passwordAtrribute);
	}

}
