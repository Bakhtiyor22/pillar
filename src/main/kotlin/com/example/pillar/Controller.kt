package com.example.pillar

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import org.springframework.data.domain.Page
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("api/v1/auth")
@Tag(name = "Authentication", description = "Authentication API endpoints")
class AuthController(private val authService: AuthService) {

    @PostMapping("/register")
    fun register(@Valid @RequestBody request: RegisterRequest): ResponseEntity<BaseMessage> {
        authService.register(request)
        return ResponseEntity.ok(BaseMessage.OK)
    }

    @GetMapping("/confirm")
    fun confirmEmail(@RequestParam token: String): ResponseEntity<BaseMessage> {
        authService.confirmEmail(token)
        return ResponseEntity.ok(BaseMessage.OK)
    }

    @PostMapping("/login")
    fun login(
        @Valid @RequestBody request: AuthRequest,
        httpRequest: HttpServletRequest
    ): ResponseEntity<TokenResponse> {
        val userAgent = httpRequest.getHeader("User-Agent")
        val token = authService.login(request, userAgent)
        return ResponseEntity.ok(token)
    }

    @PostMapping("/refresh")
    fun refreshToken(@RequestBody request: RefreshTokenRequest): ResponseEntity<TokenResponse> {
        val token = authService.refreshToken(request)
        return ResponseEntity.ok(token)
    }

    @PostMapping("/password-reset/request")
    fun requestPasswordReset(@RequestParam email: String): ResponseEntity<BaseMessage> {
        authService.initiatePasswordReset(email)
        return ResponseEntity.ok(BaseMessage.OK)
    }

    @PostMapping("/password-reset/confirm")
    fun resetPassword(
        @RequestParam email: String,
        @RequestParam code: String,
        @RequestParam newPassword: String
    ): ResponseEntity<BaseMessage> {
        authService.resetPassword(email, code, newPassword)
        return ResponseEntity.ok(BaseMessage.OK)
    }
}

@RestController
@RequestMapping("api/v1/medications")
class MedicationController(private val medicationService: MedicationService) {

    @GetMapping
    fun getAllMedications(
        @RequestParam(defaultValue = "0") page: Int,
        @RequestParam(defaultValue = "10") size: Int,
        @RequestParam(defaultValue = "id") sortBy: String,
        @RequestParam(defaultValue = "asc") sortDir: String
    ): ResponseEntity<Page<MedicationDTO>> {
        val direction = if (sortDir.equals("desc", ignoreCase = true))
            org.springframework.data.domain.Sort.Direction.DESC
        else
            org.springframework.data.domain.Sort.Direction.ASC

        val pageable = org.springframework.data.domain.PageRequest.of(
            page, size, org.springframework.data.domain.Sort.by(direction, sortBy)
        )

        return ResponseEntity.ok(medicationService.getAllMedications(pageable))
    }

    @GetMapping("/{id}")
    fun getMedicationById(@PathVariable id: Long): ResponseEntity<MedicationDTO> {
        return ResponseEntity.ok(medicationService.getMedicationById(id))
    }

    @PostMapping
    fun createMedication(@Valid @RequestBody request: createMedicationRequest): ResponseEntity<MedicationDTO> {
        return ResponseEntity.ok(medicationService.createMedication(request))
    }

    @PutMapping("/{id}")
    fun updateMedication(
        @PathVariable id: Long,
        @Valid @RequestBody request: updateMedicationRequest
    ): ResponseEntity<MedicationDTO> {
        return ResponseEntity.ok(medicationService.updateMedication(id, request))
    }

    @DeleteMapping("/{id}")
    fun deleteMedication(@PathVariable id: Long): ResponseEntity<BaseMessage> {
        medicationService.deleteMedication(id)
        return ResponseEntity.ok(BaseMessage.OK)
    }
}