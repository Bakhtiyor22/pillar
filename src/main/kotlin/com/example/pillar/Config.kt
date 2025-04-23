package com.example.pillar

import com.example.demo.JwtAuthFilter
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.boot.CommandLineRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.support.ResourceBundleMessageSource
import org.springframework.data.domain.AuditorAware
import org.springframework.data.jpa.repository.config.EnableJpaAuditing
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
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
    private val customUserDetailsService: CustomUserDetailsService,
    private val jwtAuthFilter: JwtAuthFilter
) {
    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    @Bean
    fun authenticationProvider(): DaoAuthenticationProvider {
        val provider = DaoAuthenticationProvider()
        provider.setUserDetailsService(customUserDetailsService)
        provider.setPasswordEncoder(passwordEncoder())
        return provider
    }

    @Bean
    fun authenticationManager(http: HttpSecurity): AuthenticationManager {
        val authBuilder = http.getSharedObject(AuthenticationManagerBuilder::class.java)
        authBuilder.userDetailsService(customUserDetailsService)
        return authBuilder.build()
    }

    @Bean
    fun filterChain(http: HttpSecurity, authManager: AuthenticationManager): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .authorizeHttpRequests { auth ->
                auth.requestMatchers(
                    "/api/v1/auth/**",
                    "/swagger-ui/**",
                    "/api-docs/**",
                    "/swagger-resources/**",
                    "/webjars/**",
                    "/swagger-ui.html"
                ).permitAll()
                auth.anyRequest().authenticated()
            }
            .cors { }
            .authenticationProvider(authenticationProvider())
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter::class.java)

        return http.build()
    }
}

@Component
class JwtAuthFilter(
    private val jwtUtils: JwtUtils,
    private val userService: CustomUserDetailsService
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
                val username = jwtUtils.extractUsername(token)
                val userDetails = userService.loadUserByUsername(username)
                val authToken = jwtUtils.getAuthentication(token, userDetails)

                SecurityContextHolder.getContext().authentication = authToken
                filterChain.doFilter(request, response)
                return
            }
        }
        filterChain.doFilter(request, response)
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