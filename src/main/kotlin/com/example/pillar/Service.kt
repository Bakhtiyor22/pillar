 package com.example.pillar

 import org.springframework.security.authentication.AuthenticationServiceException
 import org.springframework.security.core.userdetails.UserDetailsService
 import org.springframework.security.core.userdetails.UsernameNotFoundException
 import org.springframework.stereotype.Component
 import org.springframework.stereotype.Service
 import org.springframework.security.authentication.AuthenticationManager
 import org.springframework.security.authentication.DisabledException
 import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
 import org.springframework.security.core.context.SecurityContextHolder
 import org.springframework.security.crypto.password.PasswordEncoder
 import org.springframework.transaction.annotation.Transactional
 import java.time.Instant
 import java.time.temporal.ChronoUnit
 import java.util.UUID
 import org.springframework.data.domain.Page
 import org.springframework.data.domain.Pageable
 import org.springframework.security.authentication.BadCredentialsException
 import org.springframework.security.core.Authentication
 import org.thymeleaf.TemplateEngine
 import org.thymeleaf.context.Context // Use org.thymeleaf.context.Context
 import java.security.SecureRandom

 @Service
 class UserPrincipalDetailsService(
     private val userRepository: UserRepository
 ) : UserDetailsService {

     override fun loadUserByUsername(email: String): UserPrincipalDetails {
         val user = userRepository.findByEmail(email)
             ?: throw UsernameNotFoundException("User not found with email: $email")

         return UserPrincipalDetails(user)
     }
 }

 @Component
 class GoogleTokenVerifierService {

//     private val CLIENT_ID: String = System.getenv("GOOGLE_CLIENT_ID")
//     private val CLIENT_ID_ANDROID: String = System.getenv("GOOGLE_CLIENT_ID_ANDROID")

//     fun verifyToken(idTokenString: String?): GoogleIdToken? {
//         try {
//             val verifier = GoogleIdTokenVerifier.Builder(
//                 NetHttpTransport(),
//                 GsonFactory.getDefaultInstance()
//             )
//                 .setAudience(listOf(CLIENT_ID, CLIENT_ID_ANDROID))
//                 .build()
//
//             return idTokenString?.let { verifier.verify(it) }
//         } catch (e: GeneralSecurityException) {
//             throw AuthenticationServiceException("Failed to verify Google ID token", e)
//         } catch (e: IOException) {
//             throw AuthenticationServiceException("Failed to verify Google ID token", e)
//         } catch (e: IllegalArgumentException) {
//             throw AuthenticationServiceException("Invalid Google ID token", e)
//         }
//     }
 }



 interface EmailService {
     fun sendConfirmationEmail(to: String, confirmationLink: String)

     fun sendPasswordResetEmail(to: String, resetCode: String)

     fun sendUserCredentialsEmail(to: String, password: String, firstName: String?, lastName: String?)

     fun sendPasswordUpdateAlertEmail(to: String, name: String?, dateTime: String?)

     fun sendEmail(to: String, subject: String, body: String)
 }

 interface AuthService {
     fun register(request: RegisterRequest): User

     fun confirmEmail(token: String): Boolean

     fun login(request: AuthRequest, userAgent: String?): TokenResponse

     fun refreshToken(request: RefreshTokenRequest): TokenResponse

     // fun authenticateWithGoogle(request: GoogleAuthRequest, userAgent: String?): TokenResponse

     fun initiatePasswordReset(email: String): Boolean

     fun resetPassword(email: String, code: String, newPassword: String): Boolean
 }


 interface MedicationService {
     fun getAllMedications(pageable: Pageable): Page<MedicationDTO>

     fun getMedicationById(id: Long): MedicationDTO

     fun createMedication(medication: createMedicationRequest): MedicationDTO

     fun updateMedication(id: Long, medication: updateMedicationRequest): MedicationDTO

     fun deleteMedication(id: Long)
 }

 @Service
 class AuthServiceImpl (
     private val userRepository: UserRepository,
     private val passwordEncoder: PasswordEncoder,
     private val authenticationManager: AuthenticationManager,
     private val jwtUtils: JwtUtils,
     private val tokenRepository: TokenRepository,
     private val sessionRepository: SessionRepository,
     private val emailService: EmailService,
     private val googleTokenVerifierService: GoogleTokenVerifierService
 ): AuthService {

     /**
      * Register a new user with email verification
      */
     @Transactional
     override fun register(request: RegisterRequest): User {
         // Check if email is already in use
         if (userRepository.existsByEmail(request.email)) {
             throw DuplicateResourceException("Email address already in use!")
         }

         // Validate password strength if needed
         // validatePasswordStrength(request.password)

         // Create new user (verified = false)
         val user = User(
             firstName = request.firstName,
             lastName = request.lastName,
             email = request.email,
             password = passwordEncoder.encode(request.password),
             role = Roles.CUSTOMER,
             confirmed = false // Email not yet verified
         )
         val savedUser = userRepository.save(user)

         // Generate and save confirmation token
         val tokenString = UUID.randomUUID().toString()
         val expiryDate = Instant.now().plus(24, ChronoUnit.HOURS) // Token valid for 24 hours

         val confirmationToken = Token(
             token = tokenString,
             tokenType = TokenType.CONFIRMATION,
             user = savedUser,
             // We need to create a Session for each Token
             session = Session(
                 user = savedUser,
                 deviceName = "Email Verification",
                 // This is a circular reference - we need to fix it after saving
                 refreshToken = null,
                 expiredAt = java.util.Date.from(expiryDate)
             )
         )

         // Save session first
         val session = sessionRepository.save(confirmationToken.session)

         // Then set the token and save it
         confirmationToken.session = session
         val savedToken = tokenRepository.save(confirmationToken)

         // Update the session with the token reference
         session.refreshToken = savedToken
         sessionRepository.save(session)

         // Send confirmation email with the token
         val confirmationLink = "http://yourdomain.com/confirm?token=$tokenString" // Change this URL
 //        emailService.sendConfirmationEmail(user.email, confirmationLink)

         return savedUser
     }

     /**
      * Confirm user's email with the provided token
      */
     @Transactional
     override fun confirmEmail(token: String): Boolean {
         val confirmationToken = tokenRepository.findByToken(token)
             ?: throw InvalidInputException("Invalid confirmation token")

         // Check if token is expired
         val session = confirmationToken.session
         val expiryDate = session.expiredAt
         if (expiryDate == null || expiryDate.toInstant().isBefore(Instant.now())) {
             // Clean up expired token
             tokenRepository.delete(confirmationToken)
             throw InvalidInputException("Confirmation token has expired")
         }

         val user = confirmationToken.user
         user.confirmed = true
         userRepository.save(user)

         // Clean up used token
         tokenRepository.delete(confirmationToken)
         sessionRepository.delete(session)

         return true
     }

     /**
      * Login with email and password
      */
     @Transactional
     override fun login(request: AuthRequest, userAgent: String?): TokenResponse {
         try {
             // Authenticate with Spring Security
             val authentication: Authentication = authenticationManager.authenticate(
                 UsernamePasswordAuthenticationToken(request.email, request.password)
             )

             // Set security context
             SecurityContextHolder.getContext().authentication = authentication

             // Get user details from authentication
             val userDetails = authentication.principal as UserPrincipalDetails
             val user = userRepository.findByIdAndDeletedFalse(userDetails.id!!)
                 ?: throw UserNotFoundException("User not found")

             // Check if user is confirmed (if using local provider)
             if (user.provider == null && user.confirmed != true) {
                 throw DisabledException("Email not verified. Please check your email for verification instructions.")
             }

             // Check for active sessions - limit to 2 sessions per user
             val activeSessions = sessionRepository.findByUserAndExpiredAtAfter(
                 user,
                 java.util.Date.from(Instant.now())
             )

             // Look for existing session from same device
             val existingSession = activeSessions.find { it.deviceName == userAgent }

             val session = if (existingSession != null) {
                 // Update existing session expiry time
                 existingSession.apply {
                     this.expiredAt = java.util.Date.from(Instant.now().plus(7, ChronoUnit.DAYS))
                 }
             } else {
                 // Limit to 2 sessions per user
                 if (activeSessions.size >= 2) {
                     throw AuthenticationServiceException(
                         "You have too many active sessions. Please log out from another device."
                     )
                 }

                 // Create new session
                 Session(
                     user = user,
                     deviceName = userAgent ?: "Unknown",
                     refreshToken = null,
                     expiredAt = java.util.Date.from(Instant.now().plus(7, ChronoUnit.DAYS))
                 )
             }

             // Save session
             val savedSession = sessionRepository.save(session)

             // Generate tokens
             val tokenResponse = jwtUtils.generateToken(user)

             // Save refresh token in database
             val refreshToken = Token(
                 token = tokenResponse.refreshToken,
                 tokenType = TokenType.REFRESH,
                 user = user,
                 session = savedSession
             )
             tokenRepository.save(refreshToken)

             // Update session with refresh token (circular reference fix)
             savedSession.refreshToken = refreshToken
             sessionRepository.save(savedSession)

             return tokenResponse

         } catch (e: BadCredentialsException) {
             throw AuthenticationServiceException("Invalid email or password")
         } catch (e: DisabledException) {
             throw e // Rethrow email verification exception
         }
     }

     /**
      * Refresh token to get new access tokens
      */
     @Transactional
     override fun refreshToken(request: RefreshTokenRequest): TokenResponse {
         val refreshTokenStr = request.refreshToken

         // First validate JWT structure and signature
         if (!jwtUtils.validateToken(refreshTokenStr)) {
             throw InvalidInputException("Invalid refresh token format")
         }

         // Get the email from the token
         val email = jwtUtils.extractUsername(refreshTokenStr)
             ?: throw InvalidInputException("Could not extract user information from token")

         // Then check if token exists in database
         val token = tokenRepository.findByToken(refreshTokenStr)
             ?: throw InvalidInputException("Refresh token not found")

         // Validate token type and user
         if (token.tokenType != TokenType.REFRESH) {
             throw InvalidInputException("Invalid token type")
         }

         val user = token.user
         if (user.email != email) {
             throw InvalidInputException("Token does not match user")
         }

         // Check if session is still valid
         val session = token.session
         if (session.expiredAt == null || session.expiredAt!!.toInstant().isBefore(Instant.now())) {
             tokenRepository.delete(token)
             throw InvalidInputException("Session has expired, please log in again")
         }

         // Generate new tokens
         val tokenResponse = jwtUtils.generateToken(user)

         // Update refresh token in database
         token.token = tokenResponse.refreshToken
         tokenRepository.save(token)

         return tokenResponse
     }

     /**
      * Authenticate with Google OAuth
      */
     // @Transactional
     // fun authenticateWithGoogle(request: GoogleAuthRequest, userAgent: String? = "Google Auth"): TokenResponse {
     //     // Verify Google token
     //     val googleIdToken = googleTokenVerifierService.verifyToken(request.idToken)
     //         ?: throw AuthenticationServiceException("Invalid Google token")

     //     val payload = googleIdToken.payload
     //     val email = payload.email
     //     val name = payload["name"] as? String
     //     val providerId = payload.subject

     //     // Check if user exists
     //     val user = userRepository.findByEmail(email) ?: run {
     //         // Create new user if not exists
     //         val newUser = User(
     //             firstName = name?.split(" ")?.firstOrNull() ?: "Google",
     //             lastName = name?.split(" ")?.lastOrNull(),
     //             email = email,
     //             password = passwordEncoder.encode(UUID.randomUUID().toString()), // Random password
     //             role = Roles.CUSTOMER,
     //             confirmed = true, // Google users are pre-verified
     //             provider = "google",
     //             providerId = providerId
     //         )
     //         userRepository.save(newUser)
     //     }

     //     // Create session
     //     val session = Session(
     //         user = user,
     //         deviceName = userAgent ?: "Google Auth",
     //         refreshToken = null,
     //         expiredAt = java.util.Date.from(Instant.now().plus(7, ChronoUnit.DAYS))
     //     )
     //     val savedSession = sessionRepository.save(session)

     //     // Generate tokens
     //     val tokenResponse = jwtUtils.generateToken(user)

     //     // Save refresh token
     //     val refreshToken = Token(
     //         token = tokenResponse.refreshToken,
     //         tokenType = TokenType.REFRESH,
     //         user = user,
     //         session = savedSession
     //     )
     //     val savedToken = tokenRepository.save(refreshToken)

     //     // Update session with token
     //     savedSession.refreshToken = savedToken
     //     sessionRepository.save(savedSession)

     //     return tokenResponse
     // }

     /**
      * Start password reset flow by sending reset code
      */
     @Transactional
     override fun initiatePasswordReset(email: String): Boolean {
         val user = userRepository.findByEmail(email)
             ?: throw UserNotFoundException("If an account exists with this email, a reset link will be sent")

         // Check if user is confirmed
         if (user.confirmed != true) {
             throw InvalidInputException("Account not verified. Please verify your email first")
         }

         // Delete any existing reset tokens for this user
         tokenRepository.findAllByUserAndTokenType(user, TokenType.PASSWORD_RESET).forEach {
             tokenRepository.delete(it)
         }

         // Generate secure random code
         val resetCode = generateSecureResetCode()

         // Create session for reset token
         val session = Session(
             user = user,
             deviceName = "Password Reset",
             refreshToken = null,
             expiredAt = java.util.Date.from(Instant.now().plus(15, ChronoUnit.MINUTES))
         )
         val savedSession = sessionRepository.save(session)

         // Create reset token
         val token = Token(
             token = resetCode,
             tokenType = TokenType.PASSWORD_RESET,
             user = user,
             session = savedSession
         )
         val savedToken = tokenRepository.save(token)

         // Update session with token
         savedSession.refreshToken = savedToken
         sessionRepository.save(savedSession)

         // Send password reset email
         emailService.sendPasswordResetEmail(user.email, resetCode)

         return true
     }

     /**
      * Reset password with verification code
      */
     @Transactional
     override fun resetPassword(email: String, code: String, newPassword: String): Boolean {
         // Find token
         val user = userRepository.findByEmail(email)
             ?: throw UserNotFoundException("User not found")

         val token = tokenRepository.findByUserEmailAndTokenType(email, TokenType.PASSWORD_RESET)
             ?: throw InvalidInputException("Invalid or expired reset code")

         // Verify token
         if (token.token != code) {
             throw InvalidInputException("Invalid reset code")
         }

         // Check if session is expired
         val session = token.session
         if (session.expiredAt == null || session.expiredAt!!.toInstant().isBefore(Instant.now())) {
             tokenRepository.delete(token)
             sessionRepository.delete(session)
             throw InvalidInputException("Reset code has expired")
         }

         // Check if new password is the same as old one
         if (passwordEncoder.matches(newPassword, user.password)) {
             throw InvalidInputException("New password cannot be the same as the old one")
         }

         // Update password
         user.password = passwordEncoder.encode(newPassword)
         userRepository.save(user)

         // Delete token and session
         tokenRepository.delete(token)
         sessionRepository.delete(session)

         return true
     }

     /**
      * Generate a secure 6-digit reset code
      */
     private fun generateSecureResetCode(): String {
         val secureRandom = SecureRandom()
         val code = secureRandom.nextInt(900000) + 100000 // 6-digit number between 100000-999999
         return code.toString()
     }
 }

 @Service // Mark as a Spring service
 class EmailServiceImpl( // Primary constructor for dependency injection
 //    private val mailSender: JavaMailSender, // Injects JavaMailSender
     private val templateEngine: TemplateEngine // Injects TemplateEngine
 ) : EmailService { // Implement the EmailService interface

     override fun sendConfirmationEmail(to: String, confirmationLink: String) {
         val context = Context() // Create a new Context
         context.setVariable("emailTitle", "Confirm Your Email")
         context.setVariable("confirmationLink", confirmationLink)
         context.setVariable("emailType", "confirmation")

         // Process the template with the context
         val htmlContent = templateEngine.process("confirmationEmailTemplate", context)

         // Call the general sendEmail function
         sendEmail(to, "Confirm Your Email", htmlContent)
     }

     override fun sendPasswordResetEmail(to: String, resetCode: String) {
         val context = Context() // Create a new Context
         context.setVariable("emailTitle", "Reset Your Password")
         context.setVariable("resetCode", resetCode)
         context.setVariable("emailType", "password_reset")

         // Process the template with the context
         val htmlContent = templateEngine.process("confirmationEmailTemplate", context)

         // Call the general sendEmail function
         sendEmail(to, "Reset Your Password", htmlContent)
     }

     override fun sendUserCredentialsEmail(to: String, password: String, firstName: String?, lastName: String?) {
         val context = Context() // Create a new Context
         // Using Kotlin's string template for name
         context.setVariable("name", "$firstName $lastName")
         context.setVariable("email", to)
         context.setVariable("password", password)
         // Using Kotlin's string template for loginLink
         context.setVariable("loginLink", "${System.getenv("BASE_URL")}/login")

         // Process the template with the context
         val htmlContent = templateEngine.process("login-credentials", context)

         // Call the general sendEmail function
         sendEmail(to, "Login Invitation - Naziir", htmlContent)
     }

     override fun sendPasswordUpdateAlertEmail(to: String, name: String?, dateTime: String?) {
         val context = Context() // Create a new Context
         context.setVariable("name", name)
         context.setVariable("updateDate", dateTime)

         // Process the template with the context
         val htmlContent = templateEngine.process("password-update-alert", context)

         // Call the general sendEmail function
         sendEmail(to, "Password Changed - Naziir", htmlContent)
     }

     override fun sendEmail(to: String, subject: String, body: String) {
         // Create a MimeMessage using the mailSender
 //        val message: MimeMessage = mailSender.createMimeMessage()
 //        // Create a MimeMessageHelper with multipart mode
 //        val helper = MimeMessageHelper(message, MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED)
 //
 //        helper.setTo(to)
 //        helper.setSubject(subject)
 //        // Set the email body, indicating it's HTML (true)
 //        helper.setText(body, true)
 //
 //        // Send the message
 //        mailSender.send(message)
     }
 }

 @Service
 class MedicationServiceImpl(
     private val medicationRepository: MedicationRepository,
     private val userRepository: UserRepository,
     private val scheduleRepository: ScheduleRepository
 ) : MedicationService {
     override fun getAllMedications(pageable: Pageable): Page<MedicationDTO> {
         val userId = getCurrentUserId()
         // Call the repository method that accepts Pageable
         val medicationPage: Page<Medication> = medicationRepository.findByUserIdAndDeletedFalse(userId, pageable)
         // Map the Page<Medication> to Page<MedicationDTO>
         return medicationPage.map { it.toDTO() }
     }


     override fun getMedicationById(id: Long): MedicationDTO {
         val userId = getCurrentUserId()
         val medication = medicationRepository.findByIdAndUserIdAndDeletedFalse(id, userId)
             ?: throw ResourceNotFoundException("Medication not found with id $id for current user")
         return medication.toDTO()
     }

     @Transactional
     override fun createMedication(request: createMedicationRequest): MedicationDTO {
         val userId = getCurrentUserId()
         val user = userRepository.findByIdAndDeletedFalse(userId)
             ?: throw UserNotFoundException("User not found")

         // Create the Medication entity
         val medication = Medication(
             pillName = request.name,
             medType = request.medType,
             dose = request.dose,
             pillType = request.pillType,
             foodInstruction = request.foodInstruction ?: FoodInstruction.ANY_TIME, // Default if null
             comment = request.instructions,
             initialPillCount = request.initialPillCount ?: 0, // Default if null
             currentPillCount = request.initialPillCount ?: 0, // Initialize current count
             refillThreshold = request.refillThreshold ?: 10, // Default if null
             isActive = request.isActive ?: true, // Default if null
             startDate = request.startDate,
             endDate = request.endDate,
             user = user,
             doctor = null, // Add logic to find/assign doctor if needed
             schedules = mutableSetOf() // Initialize empty set
         )

         // Save medication first to get its ID
         val savedMedication = medicationRepository.save(medication)

         // Create and save Schedule entities if scheduling info is provided
         if (request.times != null && request.frequencyType != null) {
             request.times.forEach { time ->
                 val schedule = Schedule(
                     frequencyType = request.frequencyType,
                     timeOfDay = time,
                     specificDaysOfWeek = request.specificDaysOfWeek?.joinToString(","), // Store as comma-separated string
                     intervalDays = request.intervalDays,
                     pillsPerDose = request.pillsPerDose ?: 1, // Default if null
                     nextReminderTime = null, // Scheduler service should calculate this
                     isActive = true,
                     medication = savedMedication, // Link to the saved medication
                     takenLogs = mutableSetOf()
                 )
                 // Add schedule to medication's set (if using CascadeType.PERSIST or ALL)
                 // savedMedication.schedules.add(schedule)
                 // Explicitly save schedule
                 scheduleRepository.save(schedule)
             }
             // If not using explicit save for schedules, save medication again after adding schedules
             // medicationRepository.save(savedMedication)
         } else {
             // Handle cases where no schedule info is provided, maybe log a warning or throw error if required
         }

         // Fetch the medication again to ensure schedules are loaded for the DTO conversion
         val finalMedication = medicationRepository.findById(savedMedication.id!!).orElseThrow {
             ResourceNotFoundException("Failed to reload medication after creation")
         }

         return finalMedication.toDTO()
     }

     @Transactional
     override fun updateMedication(id: Long, request: updateMedicationRequest): MedicationDTO {
         val userId = getCurrentUserId()
         val medication = medicationRepository.findByIdAndUserIdAndDeletedFalse(id, userId)
             ?: throw ResourceNotFoundException("Medication not found with id $id for current user")

         // Update Medication fields from request if they are not null
         request.name?.let { medication.pillName = it }
         request.dosage?.toDoubleOrNull()?.let { medication.dose = it } // Safely convert dosage string
         request.form?.let { medication.pillType = it }
         request.foodInstruction?.let { medication.foodInstruction = it }
         request.instructions?.let { medication.comment = it }
         request.initialPillCount?.let {
             medication.initialPillCount = it
             // Optionally reset currentPillCount if initial count changes,
             // or handle this based on specific requirements (e.g., only on refill action)
             // medication.currentPillCount = it
         }
         request.refillThreshold?.let { medication.refillThreshold = it }
         request.isActive?.let { medication.isActive = it }

         // Always update dates as they are not optional in the request DTO
         medication.startDate = request.startDate
         medication.endDate = request.endDate

         // Handle schedule updates if schedule info is present in the request
         if (request.times != null && request.frequencyType != null) {
             // 1. Delete existing schedules for this medication
             scheduleRepository.deleteByMedicationId(medication.id!!) // Assuming deleteByMedicationId exists

             // Clear the collection in the entity to avoid Hibernate state issues
             medication.schedules.clear()

             // 2. Create new schedules based on the request
             request.times.forEach { time ->
                 val newSchedule = Schedule(
                     frequencyType = request.frequencyType,
                     timeOfDay = time,
                     specificDaysOfWeek = request.specificDaysOfWeek?.joinToString(","),
                     intervalDays = request.intervalDays,
                     pillsPerDose = request.pillsPerDose ?: 1,
                     nextReminderTime = null,
                     isActive = true,
                     medication = medication,
                     takenLogs = mutableSetOf()
                 )
                 // Explicitly save new schedule
                 scheduleRepository.save(newSchedule)
                 // Add to collection if using cascade persist/merge
                 // medication.schedules.add(newSchedule)
             }
         }

         // Save the updated medication entity (cascading might save schedules if configured)
         val updatedMedication = medicationRepository.save(medication)

         // Fetch again to ensure schedules are loaded for DTO conversion
         val finalMedication = medicationRepository.findById(updatedMedication.id!!).orElseThrow {
             ResourceNotFoundException("Failed to reload medication after update")
         }

         return finalMedication.toDTO()
     }

     @Transactional
     override fun deleteMedication(id: Long) {
         val userId = getCurrentUserId()
         val medication = medicationRepository.findByIdAndUserIdAndDeletedFalse(id, userId)
             ?: throw ResourceNotFoundException("Medication not found with id $id for current user")

         // Option 1: Soft delete (using BaseRepository's trash method)
         medicationRepository.trash(id)
         // Also soft-delete associated schedules if they don't have a 'deleted' flag
         // Or hard-delete schedules:
         scheduleRepository.deleteByMedicationId(id)


         // Option 2: Hard delete (if not using soft delete)
         // scheduleRepository.deleteByMedicationId(id) // Delete schedules first
         // medicationRepository.delete(medication)
     }
 }


