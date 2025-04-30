package com.example.pillar

import com.fasterxml.jackson.annotation.JsonInclude
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.LocalTime
import java.util.Date
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
    val medType: MedType,
    @NotBlank(message = "Medication name is required")
    val name: String,
    val dose: Double,
    val pillType: PillType,
    val foodInstruction: FoodInstruction?,
    val initialPillCount: Int?,
    val refillThreshold: Int?,
    val isActive: Boolean?,
    val instructions: String?,
    val frequencyType: FrequencyType?,
    val times: List<LocalTime>?, // List of specific times, e.g., ["08:00", "20:00"]
    val pillsPerDose: Int?,
    val specificDaysOfWeek: List<String>?, // e.g., ["MONDAY", "WEDNESDAY"]
    val intervalDays: Int?,
    val startDate: LocalDate,
    val endDate: LocalDate
)

data class updateMedicationRequest(
    val name: String?, // Allow partial updates
    val dosage: String?,
    val form: PillType?,
    val foodInstruction: FoodInstruction?,
    val instructions: String?,
    val initialPillCount: Int?,
    val refillThreshold: Int?,
    val isActive: Boolean?,
    val frequencyType: FrequencyType?,
    val times: List<LocalTime>?,
    val pillsPerDose: Int?,
    val specificDaysOfWeek: List<String>?,
    val intervalDays: Int?,
    val startDate: LocalDate,
    val endDate: LocalDate
)

data class MedicationDTO(
    val id: Long,
    val name: String,
    val dosage: String?,
    val form: PillType?,
    val frequencyType: FrequencyType?, // Added
    val startDate: LocalDate?,
    val endDate: LocalDate?,
    val times: List<LocalTime>?,
    val instructions: String?,
    val userId: Long
)

fun Medication.toDTO(): MedicationDTO {
    val schedules = this.schedules.toList()

    return MedicationDTO(
        id = this.id ?: throw IllegalStateException("Medication ID is null"),
        name = this.pillName,
        dosage = this.dose.toString(),
        form = this.pillType,
        frequencyType = schedules.firstOrNull()?.frequencyType,
        startDate = this.startDate,
        endDate = this.endDate,
        times = schedules.map { it.timeOfDay },
        instructions = this.comment,
        userId = this.user.id ?: throw IllegalStateException("Medication user ID is null")
    )
}