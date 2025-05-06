 package com.example.pillar

 import org.slf4j.LoggerFactory
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
 import org.springframework.scheduling.annotation.Scheduled
 import org.springframework.security.authentication.BadCredentialsException
 import org.springframework.security.core.Authentication
 import org.springframework.stereotype.Repository
 import org.thymeleaf.TemplateEngine
 import org.thymeleaf.context.Context // Use org.thymeleaf.context.Context
 import java.security.SecureRandom
 import java.time.DayOfWeek
 import java.time.Duration
 import java.time.LocalDate
 import java.time.LocalDateTime
 import java.time.ZoneId
 import java.time.ZonedDateTime
 import java.time.format.DateTimeFormatter

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

 interface NotificationService {

     fun sendMedicationReminder(schedule: Schedule): Boolean

     fun sendLowStockAlert(medication: Medication): Boolean

     fun updateLastRefillReminderSent(medication: Medication): Medication
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

     override fun register(request: RegisterRequest): User {
         ValidationUtils.validateRegistration(request)

         if (userRepository.existsByEmail(request.email)) {
             throw DuplicateResourceException("Email address already in use!")
         }

         val user = User(
             firstName = request.firstName,
             lastName = request.lastName,
             email = request.email,
             password = passwordEncoder.encode(request.password),
             role = Roles.CUSTOMER,
             confirmed = false // Email not yet verified
         )
         val savedUser = userRepository.save(user)

         val tokenString = UUID.randomUUID().toString()
         val expiryDate = Instant.now().plus(24, ChronoUnit.HOURS)

         val confirmationToken = Token(
             token = tokenString,
             tokenType = TokenType.CONFIRMATION,
             user = savedUser,
             session = Session(
                 user = savedUser,
                 deviceName = "Email Verification",
                 refreshToken = null,
                 expiredAt = java.util.Date.from(expiryDate)
             )
         )

         val session = sessionRepository.save(confirmationToken.session)

         confirmationToken.session = session
         val savedToken = tokenRepository.save(confirmationToken)

         session.refreshToken = savedToken
         sessionRepository.save(session)

         val confirmationLink = "http://yourdomain.com/confirm?token=$tokenString"
 //        emailService.sendConfirmationEmail(user.email, confirmationLink)

         return savedUser
     }

     override fun confirmEmail(token: String): Boolean {
         val confirmationToken = tokenRepository.findByToken(token)
             ?: throw InvalidInputException("Invalid confirmation token")

         val session = confirmationToken.session
         val expiryDate = session.expiredAt
         if (expiryDate == null || expiryDate.toInstant().isBefore(Instant.now())) {
             tokenRepository.delete(confirmationToken)
             throw InvalidInputException("Confirmation token has expired")
         }

         val user = confirmationToken.user
         user.confirmed = true
         userRepository.save(user)
         tokenRepository.delete(confirmationToken)
         sessionRepository.delete(session)

         return true
     }

     @Transactional
     override fun login(request: AuthRequest, userAgent: String?): TokenResponse {
         try {
             val authentication: Authentication = authenticationManager.authenticate(
                 UsernamePasswordAuthenticationToken(request.email, request.password)
             )

             SecurityContextHolder.getContext().authentication = authentication

             val userDetails = authentication.principal as UserPrincipalDetails
             val user = userRepository.findByIdAndDeletedFalse(userDetails.id!!)
                 ?: throw UserNotFoundException("User not found")

             if (user.provider == null && user.confirmed != true) {
                 throw DisabledException("Email not verified. Please check your email for verification instructions.")
             }

             val activeSessions = sessionRepository.findByUserAndExpiredAtAfter(
                 user,
                 java.util.Date.from(Instant.now())
             )

             val existingSessionOnDevice = activeSessions.find { it.deviceName == userAgent }

             val sessionToUse: Session
             val tokenResponse = jwtUtils.generateToken(user) // Generate new JWTs (access & refresh strings)

             if (existingSessionOnDevice != null) {
                 sessionToUse = existingSessionOnDevice.apply {
                     this.expiredAt = java.util.Date.from(Instant.now().plus(7, ChronoUnit.DAYS))
                 }
                 // Save session to update its expiry
                 sessionRepository.save(sessionToUse)

                 // Handle the refresh token for this existing session
                 val currentRefreshTokenEntity = sessionToUse.refreshToken
                 if (currentRefreshTokenEntity != null) {
                     // Existing token found, update its value
                     currentRefreshTokenEntity.token = tokenResponse.refreshToken
                     // Potentially update other fields of the Token entity if necessary
                     tokenRepository.save(currentRefreshTokenEntity)
                 } else {
                     // Session existed, but no refresh token was linked. Create and link one.
                     val newRefreshTokenEntity = Token(
                         token = tokenResponse.refreshToken,
                         tokenType = TokenType.REFRESH,
                         user = user,
                         session = sessionToUse
                     )
                     tokenRepository.save(newRefreshTokenEntity)
                     sessionToUse.refreshToken = newRefreshTokenEntity // Establish the link in the session object
                     sessionRepository.save(sessionToUse) // Persist the new token link in the session
                 }
             } else {
                 // No session for this device, create a new one
                 if (activeSessions.size >= 2) {
                     // Throwing a more specific exception might be better here
                     throw AuthenticationServiceException("User already has the maximum number of active sessions.")
                 }

                 sessionToUse = Session(
                     user = user,
                     deviceName = userAgent ?: "Unknown",
                     refreshToken = null, // Will be set after token creation
                     expiredAt = java.util.Date.from(Instant.now().plus(7, ChronoUnit.DAYS))
                 )
                 // Save the new session first to ensure it has an ID
                 sessionRepository.save(sessionToUse)

                 // Create and link the new refresh token
                 val newRefreshTokenEntity = Token(
                     token = tokenResponse.refreshToken,
                     tokenType = TokenType.REFRESH,
                     user = user,
                     session = sessionToUse
                 )
                 tokenRepository.save(newRefreshTokenEntity)
                 sessionToUse.refreshToken = newRefreshTokenEntity // Establish the link in the session object
                 sessionRepository.save(sessionToUse) // Persist the new token link in the session
             }

             return tokenResponse

         } catch (e: BadCredentialsException) {
             throw AuthenticationServiceException("Invalid email or password")
         } catch (e: DisabledException) {
             throw e
         }
     }

     override fun refreshToken(request: RefreshTokenRequest): TokenResponse {
         val refreshTokenStr = request.refreshToken

         if (!jwtUtils.validateToken(refreshTokenStr)) {
             throw InvalidInputException("Invalid refresh token format")
         }

         val email = jwtUtils.extractUsername(refreshTokenStr)
             ?: throw InvalidInputException("Could not extract user information from token")

         val token = tokenRepository.findByToken(refreshTokenStr)
             ?: throw InvalidInputException("Refresh token not found")

         if (token.tokenType != TokenType.REFRESH) {
             throw InvalidInputException("Invalid token type")
         }

         val user = token.user
         if (user.email != email) {
             throw InvalidInputException("Token does not match user")
         }

         val session = token.session
         if (session.expiredAt == null || session.expiredAt!!.toInstant().isBefore(Instant.now())) {
             tokenRepository.delete(token)
             throw InvalidInputException("Session has expired, please log in again")
         }

         val tokenResponse = jwtUtils.generateToken(user)

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

         val token = Token(
             token = resetCode,
             tokenType = TokenType.PASSWORD_RESET,
             user = user,
             session = savedSession
         )
         val savedToken = tokenRepository.save(token)

         savedSession.refreshToken = savedToken
         sessionRepository.save(savedSession)

         emailService.sendPasswordResetEmail(user.email, resetCode)

         return true
     }

     override fun resetPassword(email: String, code: String, newPassword: String): Boolean {
         val user = userRepository.findByEmail(email)
             ?: throw UserNotFoundException("User not found")

         val token = tokenRepository.findByUserEmailAndTokenType(email, TokenType.PASSWORD_RESET)
             ?: throw InvalidInputException("Invalid or expired reset code")

         if (token.token != code) {
             throw InvalidInputException("Invalid reset code")
         }

         val session = token.session
         if (session.expiredAt == null || session.expiredAt!!.toInstant().isBefore(Instant.now())) {
             tokenRepository.delete(token)
             sessionRepository.delete(session)
             throw InvalidInputException("Reset code has expired")
         }

         if (passwordEncoder.matches(newPassword, user.password)) {
             throw InvalidInputException("New password cannot be the same as the old one")
         }

         user.password = passwordEncoder.encode(newPassword)
         userRepository.save(user)

         tokenRepository.delete(token)
         sessionRepository.delete(session)

         return true
     }

     private fun generateSecureResetCode(): String {
         val secureRandom = SecureRandom()
         val code = secureRandom.nextInt(900000) + 100000
         return code.toString()
     }
 }

 @Service
 class EmailServiceImpl( // Primary constructor for dependency injection
 //    private val mailSender: JavaMailSender, // Injects JavaMailSender
     private val templateEngine: TemplateEngine // Injects TemplateEngine
 ) : EmailService { // Implement the EmailService interface

     override fun sendConfirmationEmail(to: String, confirmationLink: String) {
         val context = Context() // Create a new Context
         context.setVariable("emailTitle", "Confirm Your Email")
         context.setVariable("confirmationLink", confirmationLink)
         context.setVariable("emailType", "confirmation")

         val htmlContent = templateEngine.process("confirmationEmailTemplate", context)

         sendEmail(to, "Confirm Your Email", htmlContent)
     }

     override fun sendPasswordResetEmail(to: String, resetCode: String) {
         val context = Context()
         context.setVariable("emailTitle", "Reset Your Password")
         context.setVariable("resetCode", resetCode)
         context.setVariable("emailType", "password_reset")

         // Process the template with the context
         val htmlContent = templateEngine.process("confirmationEmailTemplate", context)

         // Call the general sendEmail function
         sendEmail(to, "Reset Your Password", htmlContent)
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
     private val scheduleRepository: ScheduleRepository,
     private val doctorRepository: DoctorRepository, // Assuming you might use this later
     private val scheduleService: ScheduleService // Inject ScheduleService
 ) : MedicationService {
     private val log = LoggerFactory.getLogger(javaClass)

     override fun getAllMedications(pageable: Pageable): Page<MedicationDTO> {
         val userId = getCurrentUserId()
         val medicationPage: Page<Medication> = medicationRepository.findByUserIdAndDeletedFalse(userId, pageable)
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

         // val doctor = if (request.doctorId != null) {
         //     doctorRepository.findByIdAndUserIdAndDeletedFalse(request.doctorId, userId)
         //         ?: throw ResourceNotFoundException("Doctor not found with id ${request.doctorId}")
         // } else {
         //     null
         // }

         val medication = Medication(
             pillName = request.name,
             medType = request.medType,
             dose = request.dose,
             pillType = request.pillType,
             foodInstruction = request.foodInstruction ?: FoodInstruction.ANY_TIME,
             comment = request.instructions,
             initialPillCount = request.initialPillCount ?: 0,
             currentPillCount = request.initialPillCount ?: 0,
             refillThreshold = request.refillThreshold ?: 5,
             isActive = request.isActive ?: true,
             startDate = request.startDate,
             endDate = request.endDate,
             user = user,
             doctor = null, // doctor = doctor,
             schedules = mutableSetOf() // Initialize with an empty set
         )

         // First save of medication to get an ID
         var savedMedication = medicationRepository.save(medication)

         if (request.times != null && request.frequencyType != null) {
             val newSchedules = mutableSetOf<Schedule>()
             request.times.forEach { time ->
                 val schedule = Schedule(
                     frequencyType = request.frequencyType,
                     timeOfDay = time,
                     specificDaysOfWeek = request.specificDaysOfWeek?.joinToString(","),
                     intervalDays = request.intervalDays,
                     pillsPerDose = request.pillsPerDose ?: 1,
                     nextReminderTime = null, // Will be calculated
                     isActive = true,
                     medication = savedMedication, // Link to the saved medication
                     takenLogs = mutableSetOf()
                 )
                 newSchedules.add(schedule)
             }
             // Add all new schedules to the medication's collection
             // Since medication.schedules is EAGER and CascadeType.ALL, saving medication will save these.
             // However, we need to save them first or ensure they are part of the medication object before the *final* save.
             // For clarity and to ensure schedules get IDs before reminder calculation if needed:
             scheduleRepository.saveAll(newSchedules) // Save new schedules
             savedMedication.schedules.addAll(newSchedules) // Add to the in-memory collection
             savedMedication = medicationRepository.save(savedMedication) // Re-save medication to persist schedule associations if not already cascaded
         }

         // Re-fetch to ensure the schedules collection is correctly loaded if there were cascading complexities
         // Or rely on the 'savedMedication' instance if confident about Hibernate's state management.
         // For robustness with EAGER fetch, savedMedication should be up-to-date.
         // Let's use the instance returned by save.

         val schedulesWithReminders = mutableSetOf<Schedule>()
         savedMedication.schedules.forEach { sch ->
             try {
                 schedulesWithReminders.add(scheduleService.calculateNextReminderTime(sch))
             } catch (e: Exception) {
                 log.error("Error calculating next reminder time for schedule ${sch.id} during medication creation: ${e.message}", e)
                 // Decide how to handle: add schedule without reminder, or skip, or rethrow
                 schedulesWithReminders.add(sch) // Add original schedule if calculation fails
             }
         }
         savedMedication.schedules = schedulesWithReminders

         return savedMedication.toDTO()
     }

     @Transactional
     override fun updateMedication(id: Long, request: updateMedicationRequest): MedicationDTO {
         val userId = getCurrentUserId()
         val medication = medicationRepository.findByIdAndUserIdAndDeletedFalse(id, userId)
             ?: throw ResourceNotFoundException("Medication not found with id $id for current user")

         // Update Medication's direct fields
         request.name?.let { medication.pillName = it }
         request.dosage?.toDoubleOrNull()?.let { medication.dose = it }
         request.form?.let { medication.pillType = it }
         request.foodInstruction?.let { medication.foodInstruction = it }
         request.instructions?.let { medication.comment = it }
         request.initialPillCount?.let {
             medication.initialPillCount = it
             // medication.currentPillCount = it // Decide if currentPillCount should reset
         }
         request.refillThreshold?.let { medication.refillThreshold = it }
         request.isActive?.let { medication.isActive = it }
         request.startDate?.let { medication.startDate = it }
         request.endDate?.let { medication.endDate = it }

         // Handle schedule updates
         if (request.times != null && request.frequencyType != null) {
             // Delete existing schedules associated with this medication
             scheduleRepository.deleteByMedicationId(medication.id!!)

             // Clear the in-memory collection of schedules from the medication entity
             // This is crucial for Hibernate to correctly manage the state and avoid issues with orphanRemoval or stale collections.
             medication.schedules.clear()

             val newSchedules = mutableSetOf<Schedule>()
             request.times.forEach { time ->
                 val newSchedule = Schedule(
                     frequencyType = request.frequencyType,
                     timeOfDay = time,
                     specificDaysOfWeek = request.specificDaysOfWeek?.joinToString(","),
                     intervalDays = request.intervalDays,
                     pillsPerDose = request.pillsPerDose ?: 1,
                     nextReminderTime = null, // Will be calculated
                     isActive = true,
                     medication = medication, // Link to the current medication instance
                     takenLogs = mutableSetOf()
                 )
                 newSchedules.add(newSchedule)
             }
             // Add all newly created schedules to the medication's collection.
             // These will be persisted when 'medication' is saved due to CascadeType.ALL.
             medication.schedules.addAll(newSchedules)
         }

         // Save the medication. This will persist changes to medication fields
         // and also persist new schedules added to its collection (due to CascadeType.ALL).
         // The schedules deleted earlier are already gone from DB.
         var updatedMedication = medicationRepository.save(medication)

         // `updatedMedication.schedules` now contains the newly saved schedules (due to EAGER fetch).
         // Their `nextReminderTime` is likely null. Let's calculate and set it.
         val finalSchedules = mutableSetOf<Schedule>()
         updatedMedication.schedules.forEach { sch ->
             try {
                 finalSchedules.add(scheduleService.calculateNextReminderTime(sch))
             } catch (e: Exception) {
                 log.error("Error calculating next reminder time for schedule ${sch.id} during medication update: ${e.message}", e)
                 finalSchedules.add(sch) // Add original schedule if calculation fails
             }
         }
         updatedMedication.schedules = finalSchedules // Update the in-memory collection with schedules that have reminder times

         return updatedMedication.toDTO()
     }

     @Transactional
     override fun deleteMedication(id: Long) {
         val userId = getCurrentUserId()
         val medication = medicationRepository.findByIdAndUserIdAndDeletedFalse(id, userId)
             ?: throw ResourceNotFoundException("Medication not found with id $id for current user")

         // Soft delete the medication (sets deleted = true)
         medicationRepository.trash(id)

         // Hard delete associated schedules. Alternatively, you could soft-delete them
         // or rely on a DB cascade if set up. Explicit deletion is clearer here.
         scheduleRepository.deleteByMedicationId(id)
     }
 }

 interface ScheduleService {

     fun calculateNextReminderTime(schedule: Schedule): Schedule

     fun getSchedulesForReminders(): List<Schedule>

     fun markMedicationTaken(scheduleId: Long, pillsTaken: Int): Schedule

     fun checkLowStockMedications(): List<Medication>
 }

 @Service
 class ScheduleServiceImpl(
     private val scheduleRepository: ScheduleRepository,
     private val medicationRepository: MedicationRepository,
     private val takenLogRepository: TakenLogRepository,
     private val userRepository: UserRepository
 ) : ScheduleService {
     private val log = LoggerFactory.getLogger(javaClass)

     @Transactional
     override fun calculateNextReminderTime(schedule: Schedule): Schedule {
         val medication = schedule.medication

         if (!medication.isActive || !schedule.isActive) {
             schedule.nextReminderTime = null
             return scheduleRepository.save(schedule)
         }

         val today = LocalDate.now()
         if (today.isBefore(medication.startDate) || today.isAfter(medication.endDate)) {
             schedule.nextReminderTime = null
             return scheduleRepository.save(schedule)
         }

         val now = Instant.now()
         val nextReminder = when (schedule.frequencyType) {
             FrequencyType.DAILY -> {
                 val reminderTime = LocalDateTime.of(today, schedule.timeOfDay)
                 val reminderInstant = reminderTime.atZone(ZoneId.systemDefault()).toInstant()

                 if (reminderInstant.isBefore(now)) {
                     reminderTime.plusDays(1).atZone(ZoneId.systemDefault()).toInstant()
                 } else {
                     reminderInstant
                 }
             }

             FrequencyType.SPECIFIC_DAYS -> {
                 val daysOfWeek = schedule.specificDaysOfWeek
                     ?.split(",")
                     ?.map { it.trim().uppercase() }
                     ?.mapNotNull {
                         try { DayOfWeek.valueOf(it) }
                         catch (e: IllegalArgumentException) { null }
                     }
                     ?: emptyList()

                 if (daysOfWeek.isEmpty()) {
                     null
                 } else {
                     var nextDate = today
                     var daysChecked = 0
                     var foundReminder: Instant? = null

                     while (daysChecked < 7 && foundReminder == null) {
                         if (daysOfWeek.contains(nextDate.dayOfWeek)) {
                             val reminderTime = LocalDateTime.of(nextDate, schedule.timeOfDay)
                             val reminderInstant = reminderTime.atZone(ZoneId.systemDefault()).toInstant()

                             if (reminderInstant.isAfter(now)) {
                                 foundReminder = reminderInstant
                             }
                         }

                         if (foundReminder == null) {
                             nextDate = nextDate.plusDays(1)
                             daysChecked++
                         }
                     }

                     foundReminder
                 }
             }

             FrequencyType.EVERY_X_DAYS -> {
                 val intervalDays = schedule.intervalDays ?: 1
                 if (intervalDays <= 0) { // Ensure interval is positive
                     log.warn("Interval days for schedule ID {} is not positive ({}). Cannot calculate reminder.", schedule.id, intervalDays)
                     null // Or handle as an error
                 } else {
                     val lastTakenLog = takenLogRepository.findTopByScheduleIdOrderByScheduledTimeDesc(schedule.id!!)

                     if (lastTakenLog != null) {
                         val lastTakenDate = Instant.ofEpochMilli(lastTakenLog.scheduledTime.toEpochMilli())
                             .atZone(ZoneId.systemDefault())
                             .toLocalDate()

                         val nextDate = lastTakenDate.plusDays(intervalDays.toLong())
                         val reminderTime = LocalDateTime.of(nextDate, schedule.timeOfDay)
                         reminderTime.atZone(ZoneId.systemDefault()).toInstant()
                     } else {
                         // Corrected logic for initial calculation for EVERY_X_DAYS
                         var candidateDate = medication.startDate
                         var potentialReminderInstant: Instant? = null

                         // Loop to find the first reminder instant that is >= now and <= medication.endDate
                         while (!candidateDate.isAfter(medication.endDate)) {
                             potentialReminderInstant = LocalDateTime.of(candidateDate, schedule.timeOfDay)
                                 .atZone(ZoneId.systemDefault()).toInstant()
                             if (!potentialReminderInstant.isBefore(now)) {
                                 // Found a suitable reminder time (on or after now)
                                 break
                             }
                             // If before now, advance to the next interval date
                             candidateDate = candidateDate.plusDays(intervalDays.toLong())
                             potentialReminderInstant = null // Reset if we are moving to next date
                         }

                         // If candidateDate went past endDate, or if loop finished without finding a suitable instant
                         if (candidateDate.isAfter(medication.endDate) && (potentialReminderInstant == null || potentialReminderInstant.isBefore(now))) {
                             null
                         } else {
                             potentialReminderInstant
                         }
                     }
                 }
             }
         }

         schedule.nextReminderTime = nextReminder
         return scheduleRepository.save(schedule)
     }

     override fun getSchedulesForReminders(): List<Schedule> {
         val now = Instant.now()
         val thirtyMinutesAgo = now.minus(30, ChronoUnit.MINUTES)

         return scheduleRepository.findByNextReminderTimeBetweenAndDeletedFalse(
             thirtyMinutesAgo,
             now
         )
     }

     @Transactional
     override fun markMedicationTaken(scheduleId: Long, pillsTaken: Int): Schedule {
         val schedule = scheduleRepository.findById(scheduleId)
             .orElseThrow { ResourceNotFoundException("Schedule not found with id $scheduleId") }

         val medication = schedule.medication
         val user = medication.user

         val takenLog = TakenLog(
             scheduledTime = schedule.nextReminderTime ?: Instant.now(),
             pillsTakenCount = pillsTaken,
             schedule = schedule,
             user = user
         )
         takenLogRepository.save(takenLog)

         medication.currentPillCount = (medication.currentPillCount - pillsTaken).coerceAtLeast(0)
         medicationRepository.save(medication)

         return calculateNextReminderTime(schedule)
     }

     override fun checkLowStockMedications(): List<Medication> {
         val oneDayAgo = Instant.now().minus(24, ChronoUnit.HOURS)

         return medicationRepository.findLowStockMedicationsNeedingReminder(
             oneDayAgo
         )
     }
 }

 @Component
 class NotificationScheduler(
     private val scheduleRepository: ScheduleRepository,
     private val medicationRepository: MedicationRepository,
     private val userRepository: UserRepository
     // private val emailService: EmailService,
     // private val telegramService: TelegramService
 ) {

     private val log = LoggerFactory.getLogger(NotificationScheduler::class.java)
     private val reminderLookAheadMinutes: Long = 1 // How many minutes ahead to check for reminders


     // Runs every minute (fixedRate = 60000 milliseconds)
     @Scheduled(fixedRate = 60000)
     @Transactional // Ensure database updates are atomic
     fun checkAndSendMedicationReminders() {
         val now = Instant.now()
         val checkUntil = now.plus(reminderLookAheadMinutes, ChronoUnit.MINUTES)
         log.debug("Checking for medication reminders between {} and {}", now, checkUntil)

         val dueSchedules = scheduleRepository.findByNextReminderTimeBetweenAndDeletedFalse(now, checkUntil)

         dueSchedules.forEach { schedule ->
             if (schedule.isActive && schedule.medication.isActive) {
                 log.info("Sending reminder for schedule ID: ${schedule.id}, Medication: ${schedule.medication.pillName}")

                 val user = schedule.medication.user
                 // emailService.sendMedicationReminder(user, schedule.medication, schedule.timeOfDay)
                 // user.telegramChatId?.let { chatId ->
                 //     telegramService.sendMedicationReminder(chatId, schedule.medication, schedule.timeOfDay)
                 // }
                 println(">>> NOTIFICATION: Take ${schedule.medication.pillName} for user ${user.email} at ${schedule.timeOfDay} <<<") // Placeholder

                 val nextReminder = calculateNextReminderTime(schedule, schedule.nextReminderTime!!) // Pass current time as base
                 if (nextReminder != null && !nextReminder.isAfter(schedule.medication.endDate.atStartOfDay(ZoneId.systemDefault()).toInstant())) {
                     schedule.nextReminderTime = nextReminder
                     scheduleRepository.save(schedule)
                     log.info("Updated next reminder time for schedule ID ${schedule.id} to $nextReminder")
                 } else {
                     // End date reached or no next time calculable, deactivate schedule?
                     schedule.isActive = false // Or handle based on requirements
                     scheduleRepository.save(schedule)
                     log.info("Deactivating schedule ID ${schedule.id} as end date reached or next time calculation failed.")
                 }
             }
         }
     }

     // Runs every 4 hours (fixedRate = 4 * 60 * 60 * 1000 milliseconds)
     @Scheduled(fixedRate = 14400000)
     @Transactional
     fun checkAndSendRefillReminders() {
         val cutoffTime = Instant.now().minus(Duration.ofDays(1)) // Don't send more than once a day
         log.debug("Checking for low stock medications needing reminder before {}", cutoffTime)

         val lowStockMeds = medicationRepository.findLowStockMedicationsNeedingReminder(cutoffTime)

         lowStockMeds.forEach { medication ->
             if (medication.isActive) {
                 log.info("Sending refill reminder for Medication ID: ${medication.id}, Name: ${medication.pillName}, Current Count: ${medication.currentPillCount}")

                 val user = medication.user
                 // emailService.sendRefillReminder(user, medication)
                 // user.telegramChatId?.let { chatId ->
                 //     telegramService.sendRefillReminder(chatId, medication)
                 // }
                 println(">>> NOTIFICATION: Refill needed for ${medication.pillName} (Current: ${medication.currentPillCount}) for user ${user.email} <<<") // Placeholder

                 medication.lastRefillReminderSentAt = Instant.now()
                 medicationRepository.save(medication)
             }
         }
     }

     private fun calculateNextReminderTime(schedule: Schedule, lastReminderDueTime: Instant): Instant? {
         val medication = schedule.medication
         val zoneId = ZoneId.systemDefault()
         val lastReminderDateTime = ZonedDateTime.ofInstant(lastReminderDueTime, zoneId)
         val scheduleTime = schedule.timeOfDay

         var potentialNextDateTime: ZonedDateTime? = null

         log.debug("Calculating next reminder for schedule ID {} based on last due time: {}", schedule.id, lastReminderDateTime)

         when (schedule.frequencyType) {
             FrequencyType.DAILY -> {
                 potentialNextDateTime = lastReminderDateTime.toLocalDate().plusDays(1).atTime(scheduleTime).atZone(zoneId)
                 log.debug("DAILY: Calculated potential next date/time: {}", potentialNextDateTime)
             }
             FrequencyType.SPECIFIC_DAYS -> {
                 val targetDays = schedule.specificDaysOfWeek?.split(',')
                     ?.mapNotNull { dayString ->
                         try {
                             DayOfWeek.valueOf(dayString.trim().uppercase())
                         } catch (e: IllegalArgumentException) {
                             log.error("Invalid day string '{}' in schedule ID {}. Skipping day.", dayString, schedule.id)
                             null
                         }
                     }?.toSet()

                 if (targetDays.isNullOrEmpty()) {
                     log.error("SPECIFIC_DAYS frequency requires valid specificDaysOfWeek for schedule ID {}. Cannot calculate next reminder.", schedule.id)
                     return null
                 }

                 log.debug("SPECIFIC_DAYS: Target days: {}, searching from date after {}", targetDays, lastReminderDateTime.toLocalDate())
                 var nextDate = lastReminderDateTime.toLocalDate().plusDays(1)
                 while (!nextDate.isAfter(medication.endDate)) {
                     if (targetDays.contains(nextDate.dayOfWeek)) {
                         potentialNextDateTime = nextDate.atTime(scheduleTime).atZone(zoneId)
                         log.debug("SPECIFIC_DAYS: Found next matching date: {}", nextDate)
                         break // Found the next valid date
                     }
                     nextDate = nextDate.plusDays(1)
                 }
                 if (potentialNextDateTime == null) {
                     log.debug("SPECIFIC_DAYS: No matching date found before or on end date {}", medication.endDate)
                 }
             }
             FrequencyType.EVERY_X_DAYS -> {
                 val interval = schedule.intervalDays
                 if (interval == null || interval <= 0) {
                     log.error("EVERY_X_DAYS frequency requires a positive intervalDays for schedule ID {}. Cannot calculate next reminder.", schedule.id)
                     return null // Cannot calculate without a valid interval
                 }
                 potentialNextDateTime = lastReminderDateTime.toLocalDate().plusDays(interval.toLong()).atTime(scheduleTime).atZone(zoneId)
                 log.debug("EVERY_X_DAYS: Calculated potential next date/time with interval {}: {}", interval, potentialNextDateTime)
             }
         }

         if (potentialNextDateTime != null && !potentialNextDateTime.toLocalDate().isAfter(medication.endDate)) {
             log.info("Successfully calculated next reminder time for schedule ID {}: {}", schedule.id, potentialNextDateTime.toInstant())
             return potentialNextDateTime.toInstant()
         } else {
             if (potentialNextDateTime != null) {
                 log.info("Calculated next reminder time {} for schedule ID {} is after the end date {}. No further reminders.", potentialNextDateTime.toLocalDate(), schedule.id, medication.endDate)
             } else {
                 log.info("Could not determine next reminder time for schedule ID {} (possibly reached end date during search).", schedule.id)
             }
             return null
         }
     }
 }

// /**
//  * Service for managing doctors
//  */
// interface DoctorService {
//     fun getAllDoctors(pageable: Pageable): Page<DoctorDTO>
//
//     fun getDoctorById(id: Long): DoctorDTO
//
//     fun createDoctor(request: CreateDoctorRequest): DoctorDTO
//
//     fun updateDoctor(id: Long, request: UpdateDoctorRequest): DoctorDTO
//
//     fun deleteDoctor(id: Long)
// }
//
// @Service
// class DoctorServiceImpl(
//     private val doctorRepository: DoctorRepository,
//     private val userRepository: UserRepository
// ) : DoctorService {
//
//     override fun getAllDoctors(pageable: Pageable): Page<DoctorDTO> {
//         val userId = getCurrentUserId()
//         val doctorPage = doctorRepository.findByUserIdAndDeletedFalse(userId, pageable)
//         return doctorPage.map { it.toDTO() }
//     }
//
//     override fun getDoctorById(id: Long): DoctorDTO {
//         val userId = getCurrentUserId()
//         val doctor = doctorRepository.findByIdAndUserIdAndDeletedFalse(id, userId)
//             ?: throw ResourceNotFoundException("Doctor not found with id $id for current user")
//         return doctor.toDTO()
//     }
//
//     @Transactional
//     override fun createDoctor(request: CreateDoctorRequest): DoctorDTO {
//         val userId = getCurrentUserId()
//         val user = userRepository.findByIdAndDeletedFalse(userId)
//             ?: throw UserNotFoundException("User not found")
//
//         val doctor = Doctor(
//             name = request.name,
//             specialty = request.specialty,
//             clinicName = request.clinicName,
//             contactPhone = request.contactPhone,
//             contactEmail = request.contactEmail,
//             addedByUser = user
//         )
//
//         val savedDoctor = doctorRepository.save(doctor)
//         return savedDoctor.toDTO()
//     }
//
//     @Transactional
//     override fun updateDoctor(id: Long, request: UpdateDoctorRequest): DoctorDTO {
//         val userId = getCurrentUserId()
//         val doctor = doctorRepository.findByIdAndUserIdAndDeletedFalse(id, userId)
//             ?: throw ResourceNotFoundException("Doctor not found with id $id for current user")
//
//         // Update fields if they are not null
//         request.name?.let { doctor.name = it }
//         request.specialty?.let { doctor.specialty = it }
//         request.clinicName?.let { doctor.clinicName = it }
//         request.contactPhone?.let { doctor.contactPhone = it }
//         request.contactEmail?.let { doctor.contactEmail = it }
//
//         val updatedDoctor = doctorRepository.save(doctor)
//         return updatedDoctor.toDTO()
//     }
//
//     @Transactional
//     override fun deleteDoctor(id: Long) {
//         val userId = getCurrentUserId()
//         val doctor = doctorRepository.findByIdAndUserIdAndDeletedFalse(id, userId)
//             ?: throw ResourceNotFoundException("Doctor not found with id $id for current user")
//
//         // Soft delete the doctor
//         doctorRepository.trash(id)
//     }
// }