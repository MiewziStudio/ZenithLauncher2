/*
 * Zalith Launcher 2
 * Copyright (C) 2025-2026 MovTery <movtery228@qq.com> and contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/gpl-3.0.txt>.
 */

package com.movtery.zalithlauncher.game.account.microsoft

import com.movtery.zalithlauncher.BuildKeys
import com.movtery.zalithlauncher.game.account.Account
import com.movtery.zalithlauncher.game.account.AccountType
import com.movtery.zalithlauncher.game.account.AccountsManager
import com.movtery.zalithlauncher.game.account.CredentialsExpiredException
import com.movtery.zalithlauncher.game.account.microsoft.MinecraftProfileException.ExceptionStatus.BLOCKED_IP
import com.movtery.zalithlauncher.game.account.microsoft.MinecraftProfileException.ExceptionStatus.FREQUENT
import com.movtery.zalithlauncher.game.account.microsoft.XboxLoginException.ExceptionStatus.BANNED
import com.movtery.zalithlauncher.game.account.microsoft.XboxLoginException.ExceptionStatus.BLOCKED_REGION
import com.movtery.zalithlauncher.game.account.microsoft.XboxLoginException.ExceptionStatus.NOT_ACCEPTED_SERVICE
import com.movtery.zalithlauncher.game.account.microsoft.XboxLoginException.ExceptionStatus.REACHED_PLAYTIME_LIMIT
import com.movtery.zalithlauncher.game.account.microsoft.XboxLoginException.ExceptionStatus.REQUIRES_PROOF_OF_AGE
import com.movtery.zalithlauncher.game.account.microsoft.XboxLoginException.ExceptionStatus.RESTRICTED
import com.movtery.zalithlauncher.game.account.microsoft.XboxLoginException.ExceptionStatus.UNDERAGE
import com.movtery.zalithlauncher.game.account.microsoft.XboxLoginException.ExceptionStatus.UNREGISTERED
import com.movtery.zalithlauncher.game.account.microsoft.models.DeviceCodeResponse
import com.movtery.zalithlauncher.game.account.microsoft.models.MinecraftAuthResponse
import com.movtery.zalithlauncher.game.account.microsoft.models.TokenResponse
import com.movtery.zalithlauncher.game.account.microsoft.models.XBLProperties
import com.movtery.zalithlauncher.game.account.microsoft.models.XBLRequest
import com.movtery.zalithlauncher.game.account.microsoft.models.XSTSAuthResult
import com.movtery.zalithlauncher.game.account.microsoft.models.XSTSProperties
import com.movtery.zalithlauncher.game.account.microsoft.models.XSTSRequest
import com.movtery.zalithlauncher.game.account.wardrobe.SkinModelType
import com.movtery.zalithlauncher.game.account.yggdrasil.findUsing
import com.movtery.zalithlauncher.game.account.yggdrasil.getPlayerProfile
import com.movtery.zalithlauncher.game.account.yggdrasil.getSkinModel
import com.movtery.zalithlauncher.path.GLOBAL_CLIENT
import com.movtery.zalithlauncher.utils.logging.Logger
import com.movtery.zalithlauncher.utils.network.httpPostJson
import com.movtery.zalithlauncher.utils.network.safeBodyAsJson
import com.movtery.zalithlauncher.utils.network.submitForm
import com.movtery.zalithlauncher.utils.string.toUuidStr
import io.ktor.client.plugins.ClientRequestException
import io.ktor.client.plugins.HttpRequestTimeoutException
import io.ktor.client.plugins.ResponseException
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.Parameters
import io.ktor.http.contentType
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.coroutines.CoroutineContext
import kotlin.time.Duration.Companion.milliseconds

private const val TAG = "MicrosoftAuth"

private val SCOPES = listOf("XboxLive.signin", "offline_access", "openid", "profile", "email")
private const val TENANT = "/consumers"

/**
 * 轮询令牌时允许的最大连续网络失败次数
 * 网络环境较差时，偶发的失败不应中断登录，但持续失败说明网络不可用，应提前放弃
 */
private const val MAX_CONSECUTIVE_POLL_FAILURES = 5

const val MICROSOFT_AUTH_URL = "https://login.microsoftonline.com"
const val LIVE_AUTH_URL = "https://login.live.com"
const val XBL_AUTH_URL = "https://user.auth.xboxlive.com"
const val XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com"
const val MINECRAFT_SERVICES_URL = "https://api.minecraftse
