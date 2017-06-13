
package com.richi.socialoauth;

import java.security.Principal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.embedded.EmbeddedServletContainerFactory;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CompositeFilter;
import org.springframework.web.servlet.ModelAndView;


@SpringBootApplication
@RestController
@EnableOAuth2Client
@EnableAuthorizationServer
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class SocialApplication extends WebSecurityConfigurerAdapter {


	public static void main(String[] args) {
		SpringApplication.run(SocialApplication.class, args);
	}

    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(SocialApplication.class);
    }



	@Autowired
	OAuth2ClientContext oauth2ClientContext;

	/** regreso a vista la propiedad del nombre de usuario */
	@RequestMapping({ "/user", "/me" })
	public Map<String, String> user(Principal principal) {
		Map<String, String> map = new LinkedHashMap<>();
		map.put("name", principal.getName());

		return map;
	}

	/** método configure() existente en nuestro "extends WebSecurityConfigurer" */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		// permitimos el acceso de recusos como login de FB y github, y webjars que son los js
		
	    
	    // Todas las solicitudes están protegidas por defecto
	    http.antMatcher("/**") 
            
	    	// La página de inicio y los puntos finales de inicio de sesión están explícitamente excluidos
            .authorizeRequests() 
                
        	// Todos los demás extremos requieren un usuario autenticado
            .antMatchers("/", "/login**", "/webjars/**", "/productos/**").permitAll() 
            
            // Los usuarios no autenticados son redirigidos a la página principal
            .anyRequest().authenticated() 
                
			/** autenticacion manual oauth */
			.and()
				.exceptionHandling()
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))

			/** habilitamos el logout que borre la sesión e invalide la cookie. */
			.and()
				.logout()
				.logoutSuccessUrl("/").permitAll()

			/**  AngularJS también ha construido en el apoyo a CSRF (lo llaman XSRF), 
			Eel servidor envíe una cookie llamada "XSRF-TOKEN" y si ve eso, 
			enviará el valor de nuevo como un encabezado llamado "X-XSRF-TOKEN". 
			*/
			.and()
				.csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())

			/** Manual oauth2   */
			.and()
				.addFilterBefore(mySsoFilter(), BasicAuthenticationFilter.class);
	}

	@Configuration
	@EnableResourceServer
	protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http.antMatcher("/me").authorizeRequests().anyRequest().authenticated();
			// @formatter:on
		}
	}

           
    
    
	/** Manejo de los redireccionamientos
	 * 
	 * Debemos conectar el filtro de manera que sea llamado en el orden correcto en nuestra aplicación Spring Boot. 
	 * Para ello necesitamos un FilterRegistrationBean:
	 * 
	 * Automatizamos el filtro ya disponible y lo registramos con un orden lo suficientemente bajo (-100) para que venga 
	 * antes del filtro principal de seguridad de resorte.  */
	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		registration.setOrder(-100);
		
		System.out.println(" Corriendo filtros...");
		
		return registration;
	}

	
	/**  tomando valores application.yml    para twitter y facebook
	 * facebook:
  			client:
	 */
	@Bean
	@ConfigurationProperties("facebook")
	public myClientResources facebook() {
		return new myClientResources();
	}
	@Bean
	@ConfigurationProperties("github")
	public myClientResources github() {
		return new myClientResources();
	}
	
	
	private Filter mySsoFilter() {
		CompositeFilter filter = new CompositeFilter();
		List<Filter> filters = new ArrayList<>();
		filters.add(ssoFilter(facebook(), "/login/facebook"));
		filters.add(ssoFilter(github(), "/login/github"));
		filter.setFilters(filters);
		
		return filter;
	}

	private Filter ssoFilter(myClientResources client, String path) {
		
		OAuth2ClientAuthenticationProcessingFilter 
			filter = new OAuth2ClientAuthenticationProcessingFilter(path);
		
		OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
		filter.setRestTemplate(template);
		UserInfoTokenServices tokenServices = new UserInfoTokenServices(
				client.getResource().getUserInfoUri(),
				 client.getClient().getClientId()
		);
		tokenServices.setRestTemplate(template);
		filter.setTokenServices(tokenServices);
		
		return filter;
	}
	

}


/**  tomando valores application.yml    para twitter y facebook
 * facebook:
			client:
 
 * Ayuda a los bean de arriba
 */
class myClientResources {
	
	/** El contenedor utiliza @NestedConfigurationProperty 
	 * 
	 * para indicar al procesador de anotaciones que rastree ese tipo de meta-datos, 
	 * ya que no representa un solo valor, sino un tipo anidado completo.
	 * 
	 * Con este envoltorio en su lugar podemos usar la misma configuración YAML que antes, 
	 * pero un solo método para cada proveedor:
	 */

	@NestedConfigurationProperty
	private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

	@NestedConfigurationProperty
	private ResourceServerProperties resource = new ResourceServerProperties();

	public AuthorizationCodeResourceDetails getClient() {
		return client;
	}

	public ResourceServerProperties getResource() {
		return resource;
	}
}

