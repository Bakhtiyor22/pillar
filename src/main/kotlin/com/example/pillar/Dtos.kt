package com.example.pillar

import com.fasterxml.jackson.annotation.JsonInclude
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import java.time.LocalDateTime
import java.util.UUID

data class BaseMessage(
    val code: Int,
    val message: String?
) {
    companion object {
        val OK = BaseMessage(200, "Success")
    }
}

data class TokenResponse(
    val accessToken: String,
    val refreshToken: String = "",
    val expired: Long
)

data class RefreshTokenRequest(
    val refreshToken: String
)

interface BaseAuthRequest {
    val role: String
}

data class AuthRequest(
    @NotBlank(message = "Email is mandatory")
    @Email(message = "Invalid email format")
    val email: String,

    @NotBlank(message = "Password is mandatory")
    @Size(min = 8, message = "Password must be at least 8 characters long.")
    val password: String,

    @NotBlank(message = "Role is mandatory")
    override val role: String
) : BaseAuthRequest

data class RegisterRequest(
    @NotBlank(message = "First name is required.")
    @Size(min = 2, max = 100, message = "First name must be between 2 and 100 characters.")
    val firstName: String,

    @Size(max = 100, message = "Last name must be up to 100 characters.")
    val lastName: String? = null,

    @field:NotBlank(message = "Email is required.")
    @field:Email(message = "Invalid email format.")
    val email: String,

    @NotBlank(message = "Password is required.")
    @Size(min = 8, message = "Password must be at least 8 characters long.")
    val password: String
)

data class GoogleAuthRequest(
    @NotBlank(message = "Id token is mandatory")
    val idToken: String,

    @NotBlank(message = "Role is mandatory")
    override val role: String
) : BaseAuthRequest

@JsonInclude(JsonInclude.Include.NON_NULL)
data class AuthResponse(
    val deviceName: String? = null,
    val userId: UUID? = null,
    val createdAt: LocalDateTime? = null,
    val updatedAt: LocalDateTime? = null,
    val expiredAt: LocalDateTime? = null,
    val token: String? = null
) {
    // In Kotlin, we don't need a separate Builder class as data classes
    // already provide copy() functionality for building objects
    companion object {
        fun builder() = AuthResponse()
    }
}

data class createMedicationRequest(
    @NotBlank(message = "Medication name is required")
    val name: String,
    val dosage: String?,
    val form: String?, // e.g., Tablet, Capsule
    val frequency: String?, // e.g., Daily, Twice a day
    val startDate: LocalDate?,
    val endDate: LocalDate?,
    val times: List<LocalTime>?, // List of specific times, e.g., ["08:00", "20:00"]
    val instructions: String?
)

data class updateMedicationRequest(
    val name: String?, // Allow partial updates
    val dosage: String?,
    val form: String?,
    val frequency: String?,
    val startDate: LocalDate?,
    val endDate: LocalDate?,
    val times: List<LocalTime>?,
    val instructions: String?
)

data class MedicationDTO(
    val id: Long,
    val name: String,
    val dosage: String?,
    val form: String?,
    val frequency: String?,
    val startDate: LocalDate?,
    val endDate: LocalDate?,
    val times: List<LocalTime>?,
    val instructions: String?,
    val userId: UUID // Include user ID for reference
)

fun Medication.toDTO(): MedicationDTO {
    // Fetch associated schedules - consider efficiency for lists
    val scheduleTimes = scheduleRepository.findByMedicationId(this.id)
                            .mapNotNull { it.scheduledTime }
    return MedicationDTO(
        id = this.id,
        name = this.name ?: "",
        dosage = this.dosage,
        form = this.form,
        frequency = this.frequency,
        startDate = this.startDate,
        endDate = this.endDate,
        times = scheduleTimes, // Use fetched schedule times
        instructions = this.instructions,
        userId = this.user?.id ?: throw IllegalStateException("Medication user is null")
    )
}