package com.kts.github.data.auth

import android.net.Uri
import androidx.core.net.toUri
import com.kts.github.data.auth.models.TokensModel
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationService
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.ClientAuthentication
import net.openid.appauth.ClientSecretPost
import net.openid.appauth.EndSessionRequest
import net.openid.appauth.GrantTypeValues
import net.openid.appauth.ResponseTypeValues
import net.openid.appauth.TokenRequest
import kotlin.coroutines.suspendCoroutine

object AppAuth {

//    Для открытия страницы авторизации в CCT нужен интент. Для этого получаем AuthorizationRequest
//    на основе заполненных раньше данных в AuthConfig:
    private val serviceConfiguration = AuthorizationServiceConfiguration(
        Uri.parse(AuthConfig.AUTH_URI),
        Uri.parse(AuthConfig.TOKEN_URI),
        null, // registration endpoint
        Uri.parse(AuthConfig.END_SESSION_URI)
    )

    fun getAuthRequest(): AuthorizationRequest {
        val redirectUri = AuthConfig.CALLBACK_URL.toUri()

        return AuthorizationRequest.Builder(
            serviceConfiguration,
            AuthConfig.CLIENT_ID,
            AuthConfig.RESPONSE_TYPE,
            redirectUri
        )
            .setScope(AuthConfig.SCOPE)
            .build()
    }

    fun getEndSessionRequest(): EndSessionRequest {
        return EndSessionRequest.Builder(serviceConfiguration)
            .setPostLogoutRedirectUri(AuthConfig.LOGOUT_CALLBACK_URL.toUri())
            .build()
    }

    fun getRefreshTokenRequest(refreshToken: String): TokenRequest {
        return TokenRequest.Builder(
            serviceConfiguration,
            AuthConfig.CLIENT_ID
        )
            .setGrantType(GrantTypeValues.REFRESH_TOKEN)
            .setScopes(AuthConfig.SCOPE)
            .setRefreshToken(refreshToken)
            .build()
    }

    suspend fun performTokenRequestSuspend(
        authService: AuthorizationService,
        tokenRequest: TokenRequest,
    ): TokensModel {
        return suspendCoroutine { continuation ->
            authService.performTokenRequest(tokenRequest, getClientAuthentication()) { response, ex ->
                when {
                    response != null -> {
                        //получение токена произошло успешно
                        val tokens = TokensModel(
                            accessToken = response.accessToken.orEmpty(),
                            refreshToken = response.refreshToken.orEmpty(),
                            idToken = response.idToken.orEmpty()
                        )
                        continuation.resumeWith(Result.success(tokens))
                    }
                    //получение токенов произошло неуспешно, показываем ошибку
                    ex != null -> { continuation.resumeWith(Result.failure(ex)) }
                    else -> error("unreachable")
                }
            }
        }
    }

    private fun getClientAuthentication(): ClientAuthentication {
        return ClientSecretPost(AuthConfig.CLIENT_SECRET)
    }

    private object AuthConfig {
        const val AUTH_URI = "https://github.com/login/oauth/authorize"
        const val TOKEN_URI = "https://github.com/login/oauth/access_token"
        const val END_SESSION_URI = "https://github.com/logout"
        const val RESPONSE_TYPE = ResponseTypeValues.CODE
        const val SCOPE = "user,repo"

        const val CLIENT_ID = "f5322253af73df2e6087"
        const val CLIENT_SECRET = "e3dabf50329a50768fb05f0e9c419782d89acc2c"
//        const val CALLBACK_URL = "ru.kts.oauth://github.com/callback"
        const val CALLBACK_URL = "ru.kts.oauth://github.com/callback"
        const val LOGOUT_CALLBACK_URL = "ru.kts.oauth://github.com/logout_callback"
    }
}