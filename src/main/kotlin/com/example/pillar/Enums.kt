package com.example.pillar

enum class Roles {
    ADMIN, CUSTOMER
}

enum class MedType {
    TABLETS,
    CAPSULE,
    INJECTION,
    PROCEDURES,
    DROPS,
    LIQUID,
    OINTMENT
}

enum class PillType {
    PILL, PIECE, MG, GR
}

enum class FoodInstruction {
    BEFORE_FOOD, WITH_FOOD, AFTER_FOOD, ANY_TIME
}

enum class FrequencyType {
    DAILY, SPECIFIC_DAYS, EVERY_X_DAYS
}

enum class ErrorCode(val code: Int) {
    GENERAL_ERROR(-1),
    USER_NOT_FOUND(-2),
    DUPLICATE_RESOURCE(-3),
    FORBIDDEN(-4),
    INVALID_INPUT(-5),
    RESOURCE_NOT_FOUND(-7),
    VALIDATION_ERROR(-8)
}

enum class TokenType {
    ACCESS, REFRESH, CONFIRMATION, PASSWORD_RESET
}

enum class NotificationType {
    MEDICATION_REMINDER,
    LOW_STOCK_ALERT,
    DOCTOR_APPOINTMENT
}

enum class MedicationStatus {
    ACTIVE, COMPLETED, ALL
}