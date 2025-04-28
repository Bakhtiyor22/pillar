package com.example.pillar

import jakarta.persistence.EntityManager
import org.springframework.context.annotation.Configuration
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.domain.Specification
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.JpaSpecificationExecutor
import org.springframework.data.jpa.repository.config.EnableJpaRepositories
import org.springframework.data.jpa.repository.support.JpaEntityInformation
import org.springframework.data.jpa.repository.support.SimpleJpaRepository
import org.springframework.data.repository.NoRepositoryBean
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
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
