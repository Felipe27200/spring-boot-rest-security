package com.luv2code.springboot.cruddemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class DemoSecurityConfig
{
    /*
    * With this Beans Spring Boot doesn't use
    * the user/pass defined inside the application.properties
    * */
    @Bean
    public InMemoryUserDetailsManager userDetailsManager()
    {
        UserDetails john = User.builder()
                .username("john")
                .password("{noop}test123")
                .roles("EMPLOYEE")
                .build();

        UserDetails mary = User.builder()
                .username("mary")
                .password("{noop}test123")
                .roles("EMPLOYEE", "MANAGER")
                .build();

        UserDetails susan = User.builder()
                .username("susan")
                .password("{noop}test123")
                .roles("EMPLOYEE", "MANAGER", "ADMIN")
                .build();

        return new InMemoryUserDetailsManager(john, mary, susan);
    }

    /*
    * +--------------------------------+
    * | RESTRICT ACCESS BASED ON ROLES |
    * +--------------------------------+
    * */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception
    {
        /*
        * This set rules of authorization for the endpoints
        * based on the given roles.
        * */
        http.authorizeHttpRequests(configurer -> {
            configurer
                /*
                * This method verify if a request matches with any rule.
                * */
                .requestMatchers(HttpMethod.GET, "api/employees").hasRole("EMPLOYEE")
                .requestMatchers(HttpMethod.GET, "api/employees/**").hasRole("EMPLOYEE")
                .requestMatchers(HttpMethod.POST, "api/employees").hasRole("MANAGER")
                .requestMatchers(HttpMethod.PUT, "api/employees").hasRole("MANAGER")
                .requestMatchers(HttpMethod.DELETE, "api/employees/**").hasRole("ADMIN");

        });

        // Use HTTP Basic Authentication
        /*
        * This set that the credentials won't alter for the
        * validation.
        * */
        http.httpBasic(Customizer.withDefaults());

        // Disable CSRF
        http.csrf(csrf -> csrf.disable());

        return http.build();
    }
}
