/* Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.systemui.securespaces

import java.util.function.Consumer
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.filter

/** No replay: a new bouncer cannot inherit an authentication from a previous screen. */
fun SecureSpaceEntryCoordinator.primaryAuthenticationProofs():
    Flow<SecureSpaceEntryCoordinator.Proof> = callbackFlow {
        val listener = Consumer<SecureSpaceEntryCoordinator.Proof> { trySend(it) }
        addProofListener(listener)
        awaitClose { removeProofListener(listener) }
    }.filter { isProofCurrent(it) }
