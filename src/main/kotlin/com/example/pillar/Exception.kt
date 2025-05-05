package com.example.pillar

import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.i18n.LocaleContextHolder
import org.springframework.context.support.ResourceBundleMessageSource
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import org.springframework.web.context.request.WebRequest
import java.util.stream.Collectors
import org.slf4j.LoggerFactory // Add this import

sealed class PillarException : RuntimeException() {
    abstract fun errorCode(): ErrorCode

    open fun getErrorMessageArguments(): Array<Any?>? = null

    fun getErrorMessage(errorMessageSource: ResourceBundleMessageSource): BaseMessage {
        val errorMessage = try {
            errorMessageSource.getMessage(
                errorCode().name,
                getErrorMessageArguments(),
                LocaleContextHolder.getLocale()
            )
        } catch (e: Exception) {
            e.message
        }
        return BaseMessage(errorCode().code, errorMessage)
    }
}

class DuplicateResourceException(private val arg: Any? = null) : PillarException() {
    override fun errorCode() = ErrorCode.DUPLICATE_RESOURCE
    override fun getErrorMessageArguments(): Array<Any?> = arrayOf(arg)
}

class ForbiddenException(private val arg: Any? = null) : PillarException() {
    override fun errorCode() = ErrorCode.FORBIDDEN
    override fun getErrorMessageArguments(): Array<Any?> = arrayOf(arg)
}

class InvalidInputException(private val arg: Any? = null) : PillarException() {
    override fun errorCode() = ErrorCode.INVALID_INPUT
    override fun getErrorMessageArguments(): Array<Any?> = arrayOf(arg)
}

class UserNotFoundException(private val arg: Any? = null) : PillarException() {
    override fun errorCode() = ErrorCode.USER_NOT_FOUND
    override fun getErrorMessageArguments(): Array<Any?> = arrayOf(arg)
}

class ResourceNotFoundException(private val arg: Any? = null) : PillarException() {
    override fun errorCode() = ErrorCode.RESOURCE_NOT_FOUND
    override fun getErrorMessageArguments(): Array<Any?> = arrayOf(arg)
}

class ValidationException(private val arg: Any? = null) : PillarException() {
    override fun errorCode() = ErrorCode.VALIDATION_ERROR
    override fun getErrorMessageArguments(): Array<Any?> = arrayOf(arg)
}

@RestControllerAdvice
class GlobalExceptionHandler(
    @Qualifier("messageSource")
    private val errorMessageSource: ResourceBundleMessageSource
) {

    private val log = LoggerFactory.getLogger(GlobalExceptionHandler::class.java)

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidationExceptions(
        ex: MethodArgumentNotValidException,
        request: WebRequest
    ): ResponseEntity<BaseMessage> {
        log.error("Validation failed: {}", ex.message)
        val errors = ex.bindingResult.fieldErrors.stream()
            .map { fieldError -> "${fieldError.field}: ${fieldError.defaultMessage}" }
            .collect(Collectors.joining(", "))

        val message = BaseMessage(
            code = ErrorCode.VALIDATION_ERROR.code,
            message = "Validation failed: [$errors]"
        )
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(message)
    }

    @ExceptionHandler(Throwable::class)
    fun handleException(ex: Throwable, request: WebRequest): ResponseEntity<BaseMessage> {
        ex.printStackTrace()
        return when (ex) {
            is PillarException -> {
                val message = ex.getErrorMessage(errorMessageSource)
                ResponseEntity.status(HttpStatus.BAD_REQUEST).body(message)
            }
            else -> {
                val fallback = BaseMessage(
                    code = ErrorCode.GENERAL_ERROR.code,
                    message = "An unexpected error occurred: ${ex.javaClass.simpleName}" // Avoid exposing raw ex.message
                )
                ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(fallback)
            }
        }
    }
}