package com.tasks.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
@Order(Ordered.HIGHEST_PRECEDENCE)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;
        
    @Autowired
    private JwtTokenProvider tokenProvider;
    
    @Override
    public void configure(WebSecurity web) throws Exception {
		web
		.ignoring()
		.antMatchers("/application/**")
		.antMatchers("/css/**")
		.antMatchers("/javascript-libs/noty/**")
		.antMatchers("/react-libs/**")
		.antMatchers("/webjars/**")
		.antMatchers("/publics/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	 http.csrf().disable();
         
         http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
         .and()
         .addFilter(new JwtAuthorizationFilter(tokenProvider, authenticationManager()))
         .authorizeRequests();
         
         http.authorizeRequests()
         
         	.antMatchers(HttpMethod.GET,  "/dashboard/**").permitAll()
             .antMatchers(HttpMethod.GET,  "/swagger-ui.html").permitAll()
             
             .antMatchers(HttpMethod.GET,  "/api/users").hasAnyRole("USER", "ADMIN")
             .antMatchers(HttpMethod.GET,  "/api/users").hasRole("ADMIN")
             
             
             .antMatchers(HttpMethod.GET,  "/api/projects").hasAnyRole("USER", "ADMIN")
             .antMatchers(HttpMethod.POST,  "/api/projects").hasRole("ADMIN")
             .antMatchers(HttpMethod.GET,  "/api/projects/*").hasAnyRole("USER", "ADMIN")
             .antMatchers(HttpMethod.DELETE,  "/api/projects/*").hasRole("ADMIN")
             .antMatchers(HttpMethod.PUT,  "/api/projects/*").hasRole("ADMIN")
             .antMatchers(HttpMethod.GET,  "/api/projects/*/tasks/**").hasAnyRole("USER", "ADMIN")
            
           
             .anyRequest().denyAll();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
    }
    
    @Bean
    public AuthenticationManager customAuthenticationManager() throws Exception {
        return authenticationManager();
    }

}
