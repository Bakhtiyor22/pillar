package com.example.pillar

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.Mockito.*
import org.mockito.ArgumentMatchers.any
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.crypto.password.PasswordEncoder
import java.time.Instant
import java.util.*

class AuthServiceImplTest {

    // Mock dependencies
    private lateinit var userRepository: UserRepository
    private lateinit var passwordEncoder: PasswordEncoder
    private lateinit var authenticationManager: AuthenticationManager
    private lateinit var jwtUtils: JwtUtils
    private lateinit var tokenRepository: TokenRepository
    private lateinit var sessionRepository: SessionRepository
    private lateinit var emailService: EmailService
    private lateinit var googleTokenVerifierService: GoogleTokenVerifierService

    // System under test
    private lateinit var authService: AuthServiceImpl

    @BeforeEach
    fun setUp() {
        userRepository = mock(UserRepository::class.java)
        passwordEncoder = mock(PasswordEncoder::class.java)
        authenticationManager = mock(AuthenticationManager::class.java)
        jwtUtils = mock(JwtUtils::class.java)
        tokenRepository = mock(TokenRepository::class.java)
        sessionRepository = mock(SessionRepository::class.java)
        emailService = mock(EmailService::class.java)
        googleTokenVerifierService = mock(GoogleTokenVerifierService::class.java)

        authService = AuthServiceImpl(
            userRepository,
            passwordEncoder,
            authenticationManager,
            jwtUtils,
            tokenRepository,
            sessionRepository,
            emailService,
            googleTokenVerifierService
        )
    }

    // Tests for register method

    @Test
    fun `register should throw exception when email is invalid`() {
        // Arrange
        val invalidRequest = RegisterRequest(
            firstName = "John",
            lastName = "Doe",
            email = "invalid-email",
            password = "Password123!"
        )

        // Act & Assert
        assertThrows<InvalidInputException> {
            authService.register(invalidRequest)
        }
    }

    @Test
    fun `register should throw exception when password is too short`() {
        // Arrange
        val invalidRequest = RegisterRequest(
            firstName = "John",
            lastName = "Doe",
            email = "john.doe@example.com",
            password = "short"
        )

        // Act & Assert
        assertThrows<InvalidInputException> {
            authService.register(invalidRequest)
        }
    }

    @Test
    fun `register should throw exception when email already exists`() {
        // Arrange
        val request = RegisterRequest(
            firstName = "John",
            lastName = "Doe",
            email = "john.doe@example.com",
            password = "Password123!"
        )

        `when`(userRepository.existsByEmail(request.email)).thenReturn(true)

        // Act & Assert
        assertThrows<DuplicateResourceException> {
            authService.register(request)
        }
    }

    @Test
    fun `register should create user and send confirmation email when valid request`() {
        // Arrange
        val request = RegisterRequest(
            firstName = "John",
            lastName = "Doe",
            email = "john.doe@example.com",
            password = "Password123!"
        )

        val encodedPassword = "encodedPassword"
        val savedUser = User(
            firstName = request.firstName,
            lastName = request.lastName,
            email = request.email,
            password = encodedPassword,
            role = Roles.CUSTOMER,
            confirmed = false
        )
        savedUser.id = 1L

        val session = Session(
            user = savedUser,
            deviceName = "Email Verification",
            refreshToken = null,
            expiredAt = Date.from(Instant.now().plusSeconds(86400))
        )
        session.id = 1L

        val token = Token(
            token = "token-uuid",
            tokenType = TokenType.CONFIRMATION,
            user = savedUser,
            session = session
        )
        token.id = 1L

        `when`(userRepository.existsByEmail(request.email)).thenReturn(false)
        `when`(passwordEncoder.encode(request.password)).thenReturn(encodedPassword)
        `when`(userRepository.save(any())).thenReturn(savedUser)
        `when`(sessionRepository.save(any())).thenReturn(session)
        `when`(tokenRepository.save(any())).thenReturn(token)

        // Act
        val result = authService.register(request)

        // Assert
        verify(userRepository).existsByEmail(request.email)
        verify(passwordEncoder).encode(request.password)
        verify(userRepository).save(any())
        verify(sessionRepository, times(2)).save(any())
        verify(tokenRepository).save(any())

        assert(result.email == request.email)
        assert(result.firstName == request.firstName)
        assert(result.lastName == request.lastName)
        assert(result.confirmed == false)
    }

    // Tests for confirmEmail method

    @Test
    fun `confirmEmail should throw exception when token is invalid`() {
        // Arrange
        val token = "invalid-token"
        `when`(tokenRepository.findByToken(token)).thenReturn(null)

        // Act & Assert
        assertThrows<InvalidInputException> {
            authService.confirmEmail(token)
        }
    }

    @Test
    fun `confirmEmail should throw exception when token is expired`() {
        // Arrange
        val token = "expired-token"
        val user = User(
            firstName = "John",
            lastName = "Doe",
            email = "john.doe@example.com",
            password = "encodedPassword",
            role = Roles.CUSTOMER,
            confirmed = false
        )

        val expiredDate = Date.from(Instant.now().minusSeconds(3600)) // 1 hour ago
        val session = Session(
            user = user,
            deviceName = "Email Verification",
            refreshToken = null,
            expiredAt = expiredDate
        )

        val confirmationToken = Token(
            token = token,
            tokenType = TokenType.CONFIRMATION,
            user = user,
            session = session
        )

        `when`(tokenRepository.findByToken(token)).thenReturn(confirmationToken)

        // Act & Assert
        assertThrows<InvalidInputException> {
            authService.confirmEmail(token)
        }

        verify(tokenRepository).delete(confirmationToken)
    }

    @Test
    fun `confirmEmail should confirm user when token is valid`() {
        // Arrange
        val token = "valid-token"
        val user = User(
            firstName = "John",
            lastName = "Doe",
            email = "john.doe@example.com",
            password = "encodedPassword",
            role = Roles.CUSTOMER,
            confirmed = false
        )

        val validDate = Date.from(Instant.now().plusSeconds(3600)) // 1 hour in future
        val session = Session(
            user = user,
            deviceName = "Email Verification",
            refreshToken = null,
            expiredAt = validDate
        )

        val confirmationToken = Token(
            token = token,
            tokenType = TokenType.CONFIRMATION,
            user = user,
            session = session
        )

        `when`(tokenRepository.findByToken(token)).thenReturn(confirmationToken)

        // Act
        val result = authService.confirmEmail(token)

        // Assert
        assert(result)
        assert(user.confirmed == true)
        verify(userRepository).save(user)
        verify(tokenRepository).delete(confirmationToken)
        verify(sessionRepository).delete(session)
    }

    // Tests for login method

    @Test
    fun `login should throw exception when credentials are invalid`() {
        // Arrange
        val request = AuthRequest(
            email = "john.doe@example.com",
            password = "wrongPassword",
            role = "CUSTOMER"
        )

        `when`(authenticationManager.authenticate(any())).thenThrow(BadCredentialsException("Invalid credentials"))

        // Act & Assert
        assertThrows<Exception> {
            authService.login(request, "userAgent")
        }
    }

    @Test
    fun `login should throw exception when email is not verified`() {
        // Arrange
        val request = AuthRequest(
            email = "john.doe@example.com",
            password = "Password123!",
            role = "CUSTOMER"
        )

        val user = User(
            firstName = "John",
            lastName = "Doe",
            email = request.email,
            password = "encodedPassword",
            role = Roles.CUSTOMER,
            confirmed = false
        )
        user.id = 1L

        val userDetails = UserPrincipalDetails(user)
        val authentication = mock(Authentication::class.java)

        `when`(authenticationManager.authenticate(any())).thenReturn(authentication)
        `when`(authentication.principal).thenReturn(userDetails)
        `when`(userRepository.findByIdAndDeletedFalse(user.id!!)).thenReturn(user)

        // Act & Assert
        assertThrows<DisabledException> {
            authService.login(request, "userAgent")
        }
    }

    @Test
    fun `login should return token response when credentials are valid`() {
        // Arrange
        val request = AuthRequest(
            email = "john.doe@example.com",
            password = "Password123!",
            role = "CUSTOMER"
        )

        val user = User(
            firstName = "John",
            lastName = "Doe",
            email = request.email,
            password = "encodedPassword",
            role = Roles.CUSTOMER,
            confirmed = true
        )
        user.id = 1L

        val userDetails = UserPrincipalDetails(user)
        val authentication = mock(Authentication::class.java)
        val tokenResponse = TokenResponse(
            accessToken = "access-token",
            refreshToken = "refresh-token",
            expired = 3600L
        )

        val session = Session(
            user = user,
            deviceName = "userAgent",
            refreshToken = null,
            expiredAt = Date.from(Instant.now().plusSeconds(604800))
        )
        session.id = 1L

        val token = Token(
            token = tokenResponse.refreshToken,
            tokenType = TokenType.REFRESH,
            user = user,
            session = session
        )
        token.id = 1L

        `when`(authenticationManager.authenticate(any())).thenReturn(authentication)
        `when`(authentication.principal).thenReturn(userDetails)
        `when`(userRepository.findByIdAndDeletedFalse(user.id!!)).thenReturn(user)
        // Mock the session repository to return an empty list for any user
        doReturn(emptyList<Session>()).`when`(sessionRepository).findByUserAndExpiredAtAfter(any(), any())
        `when`(sessionRepository.save(any())).thenReturn(session)
        `when`(jwtUtils.generateToken(user)).thenReturn(tokenResponse)
        `when`(tokenRepository.save(any())).thenReturn(token)

        // Act
        val result = authService.login(request, "userAgent")

        // Assert
        assert(result.accessToken == tokenResponse.accessToken)
        assert(result.refreshToken == tokenResponse.refreshToken)
        assert(result.expired == tokenResponse.expired)

        verify(authenticationManager).authenticate(any())
        verify(userRepository).findByIdAndDeletedFalse(user.id!!)
        verify(sessionRepository).findByUserAndExpiredAtAfter(any(), any())
        verify(sessionRepository, times(2)).save(any())
        verify(jwtUtils).generateToken(user)
        verify(tokenRepository).save(any())
    }
}
