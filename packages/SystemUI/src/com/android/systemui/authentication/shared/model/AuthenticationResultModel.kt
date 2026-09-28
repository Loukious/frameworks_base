/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.systemui.authentication.shared.model

import android.os.UserHandle
import kotlin.time.Duration

/** Models the result of an authentication attempt. */
data class AuthenticationResultModel(
    /** Whether authentication was successful. */
    val isSuccessful: Boolean = false,
    /** If [isSuccessful] is `false`, how long the user must wait before trying again. */
    val lockoutDuration: Duration = Duration.ZERO,
    /** If [isSuccessful] is `false`, whether the attempt was a duplicate. */
    val isDuplicate: Boolean = false,
    /** Identity actually sent to the hardware verifier, including failed/throttled attempts. */
    val checkedUserId: Int = UserHandle.USER_NULL,
    /** A native handoff owns completion; this response cannot directly dismiss keyguard. */
    val isHandoffPending: Boolean = false,
    /** Hardware retry, cancellation or service failure cannot establish a wrong credential. */
    val isInconclusive: Boolean = false,
) {
    /** A successful result identifies a user; an unsuccessful result never authenticates one. */
    val matchedUserId: Int?
        get() = checkedUserId.takeIf { isSuccessful && it != UserHandle.USER_NULL }
}
