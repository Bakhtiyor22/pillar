package com.example.pillar

import jakarta.persistence.*
import org.hibernate.annotations.ColumnDefault
import org.springframework.data.annotation.CreatedBy
import org.springframework.data.annotation.CreatedDate
import org.springframework.data.annotation.LastModifiedBy
import org.springframework.data.annotation.LastModifiedDate
import org.springframework.data.jpa.domain.support.AuditingEntityListener
import java.time.Instant
import java.time.LocalDate
import java.time.LocalTime
import java.time.ZonedDateTime
import java.util.*

@MappedSuperclass
@EntityListeners(AuditingEntityListener::class)
open class BaseEntity(
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) var id: Long? = null,
    @CreatedDate @Temporal(TemporalType.TIMESTAMP) var createdDate: Date? = null,
    @LastModifiedDate @Temporal(TemporalType.TIMESTAMP) var modifiedDate: Date? = null,
    @CreatedBy var createdBy: String? = null,
    @LastModifiedBy var modifiedBy: String? = null,
    @Column(nullable = false) @ColumnDefault(value = "false") var deleted: Boolean = false,
)

@Entity
@Table(name = "users")
class User(
    var firstName: String?,
    var lastName: String?,
    @Column(nullable = false, unique = true)
    var email: String,
    @Column(nullable = false)
    var password: String,
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    var role: Roles,
    var telegramChatId: Long? = null,
    var provider: String? = null,
    var providerId: String? = null,
    var confirmed: Boolean? = false
) : BaseEntity()

@Entity
@Table(name = "doctors")
class Doctor(
    @Column(nullable = false)
    var name: String,

    var specialty: String? = null,
    var clinicName: String? = null,
    var contactPhone: String? = null,
    var contactEmail: String? = null,

    @OneToMany(mappedBy = "doctor", cascade = [CascadeType.PERSIST, CascadeType.MERGE], fetch = FetchType.LAZY) // Medications prescribed by this doctor
    var medicationsPrescribed: MutableSet<Medication> = mutableSetOf(),

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "added_by_user_id")
    var addedByUser: User? = null

) : BaseEntity() {
    // Ensure doctors with the same name (and potentially other identifiers like clinic) are unique if needed
    // Add unique constraints in @Table or use application logic
}

@Entity
@Table(name = "medications")
class Medication(
    @Column(nullable = false)
    var pillName: String,

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    var medType: MedType,
    var dose: Double,
    @Enumerated(value = EnumType.STRING)
    var pillType: PillType,
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    var foodInstruction: FoodInstruction,
    @Column(columnDefinition = "TEXT")
    var comment: String?,
    @Column(nullable = false)
    var initialPillCount: Int,
    @Column(nullable = false)
    var currentPillCount: Int,
    @Column(nullable = false)
    @ColumnDefault(value = "10")
    var refillThreshold: Int = 10,
    @Column(nullable = false)
    @ColumnDefault(value = "true")
    var isActive: Boolean = true,
    var lastRefillReminderSentAt: Instant? = null,
    var startDate: LocalDate,
    var endDate: LocalDate,

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    var user: User,

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "doctor_id", nullable = true)
    var doctor: Doctor?,

    @OneToMany(mappedBy = "medication", cascade = [CascadeType.ALL], orphanRemoval = true, fetch = FetchType.EAGER)
    var schedules: MutableSet<Schedule> = mutableSetOf()
) : BaseEntity()

@Entity
@Table(name = "schedules")
class Schedule(
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    var frequencyType: FrequencyType,
    @Column(nullable = false)
    var timeOfDay: LocalTime,
    var specificDaysOfWeek: String? = null,
    var intervalDays: Int? = null,
    @Column(nullable = false)
    var pillsPerDose: Int = 1,
    @Column(nullable = true)
    var nextReminderTime: Instant? = null,
    @Column(nullable = false)
    @ColumnDefault(value = "true")
    var isActive: Boolean = true,

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "medication_id", nullable = false)
    var medication: Medication,

    @OneToMany(mappedBy = "schedule", cascade = [CascadeType.ALL], orphanRemoval = true, fetch = FetchType.LAZY)
    var takenLogs: MutableSet<TakenLog> = mutableSetOf()
) : BaseEntity()

@Entity
@Table(name = "taken_logs")
class TakenLog(
    @Column(nullable = false)
    var scheduledTime: Instant,
    @Column(nullable = false)
    var pillsTakenCount: Int,

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "schedule_id", nullable = false)
    var schedule: Schedule,

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    var user: User
) : BaseEntity()

@Entity
@Table(name = "tokens")
class Token(
    var token: String,
    var tokenType: TokenType,
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(nullable = false, name = "user_id")
    var user: User,
    @OneToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "session_id")
    var session: Session
): BaseEntity()

@Entity
@Table(name = "sessions")
class Session(
    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    var user: User,

    var deviceName: String,

    @OneToOne(mappedBy = "session", cascade = [CascadeType.ALL], fetch = FetchType.EAGER)
    var refreshToken: Token?,

    @Temporal(TemporalType.TIMESTAMP) var expiredAt: Date? = null
): BaseEntity()




