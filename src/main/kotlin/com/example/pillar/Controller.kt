package com.example.pillar

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.data.web.PageableDefault
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("api/v1/auth")
@Tag(name = "Authentication", description = "Authentication API endpoints")
class AuthController(private val authService: AuthService) {

    @PostMapping("/register")
    fun register(@Valid @RequestBody request: RegisterRequest) = authService.register(request)

    @GetMapping("/confirm")
    fun confirmEmail(@RequestParam token: String) = authService.confirmEmail(token)

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
    fun refreshToken(@RequestBody request: RefreshTokenRequest) = authService.refreshToken(request)

    @PostMapping("/password-reset/request")
    fun requestPasswordReset(@RequestParam email: String) = authService.initiatePasswordReset(email)

    @PostMapping("/password-reset/confirm")
    fun resetPassword(
        @RequestParam email: String,
        @RequestParam code: String,
        @RequestParam newPassword: String
    ) = authService.resetPassword(email, code, newPassword)
}

@RestController
@RequestMapping("api/v1/medications")
class MedicationController(private val medicationService: MedicationService) {

    @GetMapping
    fun getAllMedications(
        @PageableDefault(size = 10) pageable: Pageable,
        @RequestParam(required = false) status: MedicationStatus?
    ) = medicationService.getAllMedications(pageable, status)

    @GetMapping("/{id}")
    fun getMedicationById(@PathVariable id: Long) = medicationService.getMedicationById(id)

    @PostMapping
    fun createMedication(@Valid @RequestBody request: createMedicationRequest) = medicationService.createMedication(request)

    @PutMapping("/{id}")
    fun updateMedication(@PathVariable id: Long, @Valid @RequestBody request: updateMedicationRequest) = medicationService.updateMedication(id, request)

    @DeleteMapping("/{id}")
    fun completeMedication(@PathVariable id: Long) = medicationService.completeMedication(id)
}

//@RestController
//@RequestMapping("api/v1/doctors")
//class DoctorController(private val doctorService: DoctorService) {
//
//    @GetMapping
//    fun getAllDoctors(@PageableDefault(size = 10) pageable: Pageable): ResponseEntity<Page<DoctorDTO>> {
//        val doctors = doctorService.getAllDoctors(pageable)
//        return ResponseEntity.ok(doctors)
//    }
//
//    @GetMapping("/{id}")
//    fun getDoctorById(@PathVariable id: Long): ResponseEntity<DoctorDTO> {
//        val doctor = doctorService.getDoctorById(id)
//        return ResponseEntity.ok(doctor)
//    }
//
//    @PostMapping
//    fun createDoctor(@RequestBody request: CreateDoctorRequest): ResponseEntity<DoctorDTO> {
//        val doctor = doctorService.createDoctor(request)
//        return ResponseEntity.status(HttpStatus.CREATED).body(doctor)
//    }
//
//    @PutMapping("/{id}")
//    fun updateDoctor(
//        @PathVariable id: Long,
//        @RequestBody request: UpdateDoctorRequest
//    ): ResponseEntity<DoctorDTO> {
//        val doctor = doctorService.updateDoctor(id, request)
//        return ResponseEntity.ok(doctor)
//    }
//
//    @DeleteMapping("/{id}")
//    fun deleteDoctor(@PathVariable id: Long): ResponseEntity<Void> {
//        doctorService.deleteDoctor(id)
//        return ResponseEntity.noContent().build()
//    }
//}