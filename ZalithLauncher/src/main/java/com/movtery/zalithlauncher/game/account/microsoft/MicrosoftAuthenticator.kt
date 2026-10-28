package com.movtery.zalithlauncher.game.account.microsoft

import com.movtery.zalithlauncher.BuildKeys
import com.movtery.zalithlauncher.game.account.Account
import com.movtery.zalithlauncher.game.account.AccountManager
import com.movtery.zalithlauncher.game.account.CredentialsExpiredException
import com.movtery.zalithlauncher.game.account.microsoft.models.*
import com.movtery.zalithlauncher.utils.logging.Logger
import com.movtery.zalithlauncher.utils.network.httpPostJson
import com.movtery.zalithlauncher.utils.network.safeBodyAsJson
import com.movtery.zalithlauncher.utils.network.submitForm
import com.movtery.zalithlauncher.utils.string.toUuidStr
import io.ktor.client.plugins.ClientRequestException
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.coroutines.delay
import kotlinx.serialization.json.JsonObject

/**
 * Zenith Launcher 2 - Microsoft Authenticator
 * Based on Amethyst / PojavLauncher logic with 5x retry
 * From: net.kdt.pojavlaunch.authenticator.microsoft.MicrosoftBackgroundLogin
 */
object MicrosoftAuthenticator {
    private const val AUTH_TOKEN_URL = "https://login.live.com/oauth20_token.srf"
    private const val XBL_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate"
    private const val XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"
    private const val MC_LOGIN_URL = "https://api.minecraftservices.com/authentication/login_with_xbox"
    private const val MC_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile"
    private const val MC_STORE_URL = "https://api.minecraftservices.com/entitlements/mcstore"

    suspend fun loginWithCode(code: String): Account {
        return performFullLogin(isRefresh = false, authCode = code)
    }

    suspend fun refreshAccount(account: Account): Account {
        val refreshToken = account.refreshToken ?: throw CredentialsExpiredException()
        return performFullLogin(isRefresh = true, authCode = refreshToken)
    }

    private suspend fun performFullLogin(isRefresh: Boolean, authCode: String): Account {
        // 1. Access Token
        val tokenResponse = acquireAccessToken(isRefresh, authCode)
        
        // 2. XBL Token
        val xblToken = acquireXBLToken(tokenResponse.accessToken)
        
        // 3. XSTS with UHS
        val (uhs, xstsToken) = acquireXsts(xblToken)
        
        // 4. Minecraft Token
        val mcToken = acquireMinecraftToken(uhs, xstsToken)

        // 5. Profile & Ownership WITH RETRY - Amethyst logic
        val profile = checkMcProfileWithRetry(mcToken)
        val ownsGame = if (profile != null) true else fetchOwnedItemsWithRetry(mcToken)

        if (profile == null && !ownsGame) {
            throw MinecraftProfileException(ExceptionStatus.NOT_OWNED)
        }

        return AccountManager.createMicrosoftAccount(
            mcName = profile?.name ?: "Demo.Player",
            mcUuid = profile?.id?.toUuidStr() ?: "00000000-0000-0000-0000-000000000000",
            mcToken = mcToken.accessToken,
            refreshToken = tokenResponse.refreshToken,
            xuid = uhs,
            expiresAt = System.currentTimeMillis() + 86400000
        )
    }

    private suspend fun acquireAccessToken(isRefresh: Boolean, authCode: String): TokenResponse {
        return submitForm(
            url = AUTH_TOKEN_URL,
            form = mapOf(
                "client_id" to "00000000402b5328",
                if (isRefresh) "refresh_token" to authCode else "code" to authCode,
                "grant_type" to if (isRefresh) "refresh_token" else "authorization_code",
                "redirect_url" to "https://login.live.com/oauth20_desktop.srf",
                "scope" to "service::user.auth.xboxlive.com::MBI_SSL"
            )
        ).safeBodyAsJson()
    }

    private suspend fun acquireXBLToken(accessToken: String): String {
        val response: XBLProperties = httpPostJson(
            url = XBL_AUTH_URL,
            body = XBLRequest(
                properties = mapOf(
                    "AuthMethod" to "RPS",
                    "SiteName" to "user.auth.xboxlive.com",
                    "RpsTicket" to accessToken
                ),
                relyingParty = "http://auth.xboxlive.com",
                tokenType = "JWT"
            )
        ).safeBodyAsJson()
        return response.token
    }

    private suspend fun acquireXsts(xblToken: String): Pair<String, String> {
        try {
            val response: XSTSAuthResult = httpPostJson(
                url = XSTS_AUTH_URL,
                body = mapOf(
                    "Properties" to mapOf(
                        "SandboxId" to "RETAIL",
                        "UserTokens" to listOf(xblToken)
                    ),
                    "RelyingParty" to "rp://api.minecraftservices.com/",
                    "TokenType" to "JWT"
                )
            ).safeBodyAsJson()
            val uhs = response.displayClaims.xui.first().uhs
            return Pair(uhs, response.token)
        } catch (e: ClientRequestException) {
            if (e.response.status.value == 401) {
                // Handle XErr from Amethyst
                val errorBody = e.response.safeBodyAsJson<JsonObject>()
                val xErr = errorBody["XErr"]?.toString()?.toLongOrNull() ?: -1L
                throw XboxLoginException.fromXErr(xErr)
            }
            throw e
        }
    }

    private suspend fun acquireMinecraftToken(uhs: String, xstsToken: String): TokenResponse {
        return httpPostJson(
            url = MC_LOGIN_URL,
            body = mapOf("identityToken" to "XBL3.0 x=$uhs;$xstsToken")
        ).safeBodyAsJson()
    }

    // ===== AMETHYST RETRY LOGIC - 5x retry =====
    private suspend fun checkMcProfileWithRetry(mcToken: String): MinecraftAuthResponse? {
        for (retryCount in 0..4) {
            try {
                val response = com.movtery.zalithlauncher.path.GLOBAL_CLIENT.get(MC_PROFILE_URL) {
                    header("Authorization", "Bearer $mcToken")
                }
                if (response.status.isSuccess()) {
                    return response.safeBodyAsJson<MinecraftAuthResponse>()
                } else if (response.status.value == 404) {
                    Logger.i("MicrosoftLogin", "No Minecraft profile, checking ownership")
                    return null
                } else if (response.status.value == 401) {
                    throw CredentialsExpiredException()
                } else if (retryCount == 4) {
                    throw RuntimeException("Failed to get profile: ${response.status}")
                }
            } catch (e: Exception) {
                if (retryCount == 4) throw e
            }
            delay(500L * (1L shl retryCount)) // 0.5s, 1s, 2s, 4s, 8s - Amethyst logic
        }
        return null
    }

    private suspend fun fetchOwnedItemsWithRetry(mcToken: String): Boolean {
        var bodyString = ""
        for (retryCount in 0..4) {
            try {
                val response = com.movtery.zalithlauncher.path.GLOBAL_CLIENT.get(MC_STORE_URL) {
                    header("Authorization", "Bearer $mcToken")
                }
                if (response.status.isSuccess()) {
                    bodyString = response.safeBodyAsJson<JsonObject>().toString()
                    break
                } else if (retryCount == 4) {
                    throw RuntimeException("Failed to get entitlements")
                }
            } catch (e: Exception) {
                if (retryCount == 4) throw e
            }
            delay(500L * (1L shl retryCount))
        }
        return try {
            bodyString.contains("product_minecraft") || bodyString.contains("game_minecraft")
        } catch (e: Exception) {
            false
        }
    }
}
