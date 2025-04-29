package com.example.pillar

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.support.ResourceBundleMessageSource
import org.springframework.data.domain.AuditorAware
import org.springframework.data.jpa.repository.config.EnableJpaAuditing
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import org.springframework.web.servlet.config.annotation.InterceptorRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor
import java.util.Locale
import java.util.Optional
import kotlin.text.startsWith
import kotlin.text.substring
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

@Configuration
@EnableJpaAuditing
class AuditingConfig {
    @Bean
    fun auditorProvider(): AuditorAware<String> {
        return AuditorAwareImpl()
    }
}

class AuditorAwareImpl : AuditorAware<String> {
    override fun getCurrentAuditor(): Optional<String> {
        val authentication = SecurityContextHolder.getContext().authentication

        return if (authentication != null && authentication.isAuthenticated &&
            authentication.principal != "anonymousUser") {
            Optional.of(authentication.name)
        } else {
            Optional.of("system")
        }
    }
}

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
class SecurityConfig(
    private val userPrincipalDetailsService: UserPrincipalDetailsService, // Changed service name
    private val jwtAuthFilter: JwtAuthFilter
) {
    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    @Bean
    fun authenticationProvider(): DaoAuthenticationProvider {
        val provider = DaoAuthenticationProvider()
        provider.setUserDetailsService(userPrincipalDetailsService) // Use the new service
        provider.setPasswordEncoder(passwordEncoder())
        return provider
    }

    // Updated way to get AuthenticationManager in Spring Boot 3+
    @Bean
    fun authenticationManager(authenticationConfiguration: AuthenticationConfiguration): AuthenticationManager {
        return authenticationConfiguration.authenticationManager
    }

    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain { // Removed authManager parameter
        http
            .csrf { it.disable() }
            .authorizeHttpRequests { auth ->
                auth.requestMatchers(
                    "/api/v1/auth/**",
                    "/swagger-ui/**",
                    "/api-docs/**",
                    "/swagger-resources/**",
                    "/webjars/**",
                    "/swagger-ui.html",
                ).permitAll()
                auth.anyRequest().authenticated()
            }
            .cors { }
            .authenticationProvider(authenticationProvider()) // Provider already configured
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter::class.java)

        return http.build()
    }
}

@Component
class JwtAuthFilter(
    private val jwtUtils: JwtUtils,
    private val userPrincipalDetailsService: UserPrincipalDetailsService // Changed service name
) : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val authHeader = request.getHeader("Authorization")
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            val token = authHeader.substring(7)
            if (jwtUtils.validateToken(token)) {
                val email = jwtUtils.extractUsername(token) // Now extracts email
                // Check if security context already has authentication
                if (email != null && SecurityContextHolder.getContext().authentication == null) {
                    val userDetails = userPrincipalDetailsService.loadUserByUsername(email) // Use the new service
                    // Double check token validity specific to userDetails if needed
                    // if (jwtUtils.isTokenValid(token, userDetails)) { // Assuming you add isTokenValid method
                    val authToken = UsernamePasswordAuthenticationToken(
                        userDetails,
                        null, // Credentials are null for token-based auth
                        userDetails.authorities
                    )
                    // Set authentication in context
                    SecurityContextHolder.getContext().authentication = authToken
                    // }
                }
            }
        }
        filterChain.doFilter(request, response) // Continue filter chain regardless
    }
}

@Configuration
class AppConfig : WebMvcConfigurer {

    @Bean(name = ["messageSource"])
    fun messageSource(): ResourceBundleMessageSource {
        val source = ResourceBundleMessageSource()
        source.setBasenames("message", "error") // Look for both files
        source.setDefaultEncoding("UTF-8")
        source.setUseCodeAsDefaultMessage(true)
        source.setFallbackToSystemLocale(false)
        return source
    }

    @Bean
    fun localeResolver(): AcceptHeaderLocaleResolver {
        val resolver = AcceptHeaderLocaleResolver()
        resolver.setDefaultLocale(Locale.forLanguageTag("uz"))
        return resolver
    }

    @Bean
    fun localeChangeInterceptor(): LocaleChangeInterceptor {
        val interceptor = LocaleChangeInterceptor()
        interceptor.paramName = "lang"
        return interceptor
    }

    override fun addInterceptors(registry: InterceptorRegistry) {
        registry.addInterceptor(localeChangeInterceptor())
    }
}

data class UserPrincipalDetails(
    val id: Long?,
    private val userEmail: String,
    private val userPassword: String,
    private val userAuthorities: Collection<GrantedAuthority>, // Changed from override val
    val provider: String = "local"
) : UserDetails {

    constructor(user: User) : this(
        id = user.id,
        userEmail = user.email,
        userPassword = user.password,
        userAuthorities = listOf(SimpleGrantedAuthority("ROLE_${user.role.name}")),
        provider = "local" // Assuming local provider for direct registration/login
    )

    // Now properly override the method from UserDetails interface
    override fun getAuthorities(): Collection<GrantedAuthority> = userAuthorities

    override fun getPassword(): String = userPassword

    override fun getUsername(): String = userEmail

    override fun isAccountNonExpired(): Boolean = true

    override fun isAccountNonLocked(): Boolean = true

    override fun isCredentialsNonExpired(): Boolean = true

    override fun isEnabled(): Boolean = true
}

