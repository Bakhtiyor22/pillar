package com.example.pillar

import io.jsonwebtoken.JwtParserBuilder
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import org.springframework.context.i18n.LocaleContextHolder
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import java.util.Base64
import java.util.Date
import java.util.regex.Pattern
import javax.crypto.SecretKey

@Component
class JwtUtils {
    private val secret: String = System.getenv("JWT_SECRET")
        ?: throw IllegalStateException("JWT_SECRET environment variable is not set")

    private val key: SecretKey by lazy {
        Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret))
    }

    private val accessTokenExpiry = 150 * 60 * 1000L

    private val refreshTokenExpiry = 70 * 24 * 60 * 60 * 1000L

    fun generateToken(user: User, locale: String? = null): TokenResponse {
        val now = Date()
        val userDetails = UserPrincipalDetails(user)

        val accessToken = Jwts.builder()
            .setSubject(userDetails.username)
            .claim("role", user.role.name)
            .claim("userId", user.id)
            .claim("locale", locale ?: LocaleContextHolder.getLocale().language)
            .claim("tokenType", "ACCESS")
            .setIssuedAt(now)
            .setExpiration(Date(now.time + accessTokenExpiry))
            .signWith(key, SignatureAlgorithm.HS256)
            .compact()

        val refreshToken = Jwts.builder()
            .setSubject(userDetails.username)
            .claim("tokenType", "REFRESH")
            .setIssuedAt(now)
            .setExpiration(Date(now.time + refreshTokenExpiry))
            .signWith(key, SignatureAlgorithm.HS256)
            .compact()

        return TokenResponse(accessToken, refreshToken, accessTokenExpiry / 1000)
    }

    fun extractLocale(token: String): String {
        val claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).body
        return claims.get("locale", String::class.java) ?: "uz"
    }

    fun validateToken(token: String): Boolean {
        return try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token)
            true
        } catch (ex: Exception) {
            false
        }
    }

    fun extractUsername(token: String): String? =
        Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).body.subject

    fun getJwtParser(): JwtParserBuilder {
        return Jwts.parserBuilder().setSigningKey(key)
    }
}

fun getCurrentUserId(): Long {
    val authentication: Authentication = SecurityContextHolder.getContext().authentication
    val userDetails = authentication.principal as? UserPrincipalDetails
        ?: throw IllegalStateException("User not authenticated")
    return userDetails.id ?: throw IllegalStateException("User ID not found in principal")
}

object ValidationUtils {

    private val EMAIL_REGEX = Pattern.compile(
        "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$"
    )

    fun validateRegistration(request: RegisterRequest) {
        // First Name Validation (already handled by @NotBlank, @Size if they worked)
        if (request.firstName.isBlank()) {
            throw InvalidInputException("First name is required.")
        }
        if (request.firstName.length < 2 || request.firstName.length > 100) {
            throw InvalidInputException("First name must be between 2 and 100 characters.")
        }

        // Last Name Validation (already handled by @Size if it worked)
        request.lastName?.let {
            if (it.length > 100) {
                throw InvalidInputException("Last name must be up to 100 characters.")
            }
        }

        // Email Validation
        if (request.email.isBlank()) {
            throw InvalidInputException("Email is required.")
        }
        if (!EMAIL_REGEX.matcher(request.email).matches()) {
            throw InvalidInputException("Invalid email format.")
        }

        // Password Validation (already handled by @NotBlank, @Size if they worked)
        if (request.password.isBlank()) {
            throw InvalidInputException("Password is required.")
        }
        if (request.password.length < 8) {
            throw InvalidInputException("Password must be at least 8 characters long.")
        }
    }
}