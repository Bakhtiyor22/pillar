package com.example.pillar

import jakarta.persistence.EntityManager
import org.springframework.context.annotation.Configuration
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.domain.Specification
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.JpaSpecificationExecutor
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.jpa.repository.config.EnableJpaRepositories
import org.springframework.data.jpa.repository.support.JpaEntityInformation
import org.springframework.data.jpa.repository.support.SimpleJpaRepository
import org.springframework.data.repository.NoRepositoryBean
import org.springframework.data.repository.findByIdOrNull
import org.springframework.data.repository.query.Param
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import java.util.*

@Configuration
@EnableJpaRepositories(
    basePackages = ["com.example.pillar"],
    repositoryBaseClass = BaseRepositoryImpl::class
)
class JpaConfig

@NoRepositoryBean
interface BaseRepository<T : BaseEntity> : JpaRepository<T, Long>, JpaSpecificationExecutor<T> {
    fun trash(id: Long): T
    fun trashList(ids: List<Long>): List<T>
    fun findAllNotDeleted(pageable: Pageable): Page<T>
    fun findAllNotDeleted(): List<T>
    fun findByIdAndDeletedFalse(id: Long): T?
}

class BaseRepositoryImpl<T : BaseEntity>(
    entityInformation: JpaEntityInformation<T, Long>,
    entityManager: EntityManager,
) : SimpleJpaRepository<T, Long>(entityInformation, entityManager), com.example.pillar.BaseRepository<T> {
    val isNotDeletedSpecification = Specification<T> { root, _, cb -> cb.equal(root.get<Boolean>("deleted"), false) }

    @Transactional
    override fun trash(id: Long) = save(findById(id).get().apply { deleted = true })
    override fun findAllNotDeleted(pageable: Pageable) = findAll(isNotDeletedSpecification, pageable)
    override fun findAllNotDeleted(): List<T> = findAll(isNotDeletedSpecification)
    override fun findByIdAndDeletedFalse(id: Long) = findByIdOrNull(id)?.run { if (deleted) null else this }

    override fun trashList(ids: List<Long>): List<T> = ids.map { trash(it) }
}

@Repository
interface UserRepository : BaseRepository<User> {
    fun findByEmail(email: String): User?
    fun existsByEmail(email: String?): Boolean
}

@Repository
interface SessionRepository : BaseRepository<Session> {
    fun deleteByUserId(id: Long)
    fun findByUserAndExpiredAtAfter(user: User, expiredAt: Date): MutableList<Session>
}

@Repository
interface TokenRepository : BaseRepository<Token> {
    fun findByToken(token: String): Token?

    fun findByUserEmailAndTokenType(email: String, tokenType: TokenType): Token?

    fun deleteByUserEmailAndTokenType(email: String, tokenType: TokenType)

    fun findAllByUserAndTokenType(user: User, tokenType: TokenType): MutableList<Token>

    fun deleteByUserId(id: Long)
}

@Repository
interface MedicationRepository : BaseRepository<Medication> {
    fun findByUserIdAndDeletedFalse(userId: Long, pageable: Pageable): Page<Medication>
    fun findByUserIdAndDeletedFalse(userId: Long): List<Medication>
    fun findByIdAndUserIdAndDeletedFalse(id: Long, userId: Long): Medication?

    @Query("""
        SELECT m FROM Medication m 
        WHERE m.deleted = false 
        AND m.currentPillCount <= m.refillThreshold 
        AND (m.lastRefillReminderSentAt IS NULL OR m.lastRefillReminderSentAt < :cutoffTime)
    """)
    fun findLowStockMedicationsNeedingReminder(@Param("cutoffTime") cutoffTime: Instant): List<Medication>
}

@Repository
interface ScheduleRepository : BaseRepository<Schedule> {
    fun findByMedicationId(medicationId: Long): List<Schedule>

    @Transactional
    @Modifying
    fun deleteByMedicationId(medicationId: Long)

    fun findByNextReminderTimeBetweenAndDeletedFalse(
        startTime: Instant,
        endTime: Instant
    ): List<Schedule>
}

@Repository
interface TakenLogRepository : BaseRepository<TakenLog> {
    fun findTopByScheduleIdOrderByScheduledTimeDesc(scheduleId: Long): TakenLog?
}

@Repository
interface DoctorRepository : BaseRepository<Doctor> {
//    fun findByUserIdAndDeletedFalse(userId: Long, pageable: Pageable): Page<Doctor>
//    fun findByUserIdAndDeletedFalse(userId: Long): List<Doctor>
//    fun findByIdAndUserIdAndDeletedFalse(id: Long, userId: Long): Doctor?
}