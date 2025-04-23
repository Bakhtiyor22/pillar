package com.example.pillar

data class BaseMessage(
    val code: Int,
    val message: String?,
){
    companion object {
        val  OK = BaseMessage(200, "Success")
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
