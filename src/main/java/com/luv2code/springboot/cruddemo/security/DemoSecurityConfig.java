package com.luv2code.springboot.cruddemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class DemoSecurityConfig
{
   /* *//*
    * With this Beans Spring Boot doesn't use
    * the user/pass defined inside the application.properties
    * /*
    @Bean
    public InMemoryUserDetailsManager userDetailsManager()
    {
        UserDetails john = User.builder()
                .username("john")
                .password("{noop}test123")
                // {noop} tells spring security that the password is in plain text
                // In the database we must set the type of encryption inside the {}
                // That tells Spring Security what encryption uses
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
    */

    /*
    * +--------------------------------+
    * | RESTRICT ACCESS BASED ON ROLES |
    * +--------------------------------+
    *
    * This is necessary to define restrictions
    * for any route or request via HTTP
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

    /*
    * +--------------------------------+
    * | DEFINE THE JDBC AUTHENTICATION |
    * +--------------------------------+
    *
    * This tells spring that it have to use
    * the jdbc authentication.
    * */
    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource) // Inject the datasource that is autoconfigured by Spring Boot
    {
        /*
        * Tells Spring Security to use JDBC authentication
        * with our data source.
        *
        * So, we will read the roles and users from the DB.
        *
        * We must have some specific tables and columns
        * for the correct use of JDBC Authentication.
        * */
        return new JdbcUserDetailsManager(dataSource);
    }
}
