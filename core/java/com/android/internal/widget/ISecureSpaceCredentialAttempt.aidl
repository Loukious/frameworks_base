/* Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.internal.widget;

/** @hide Cancellation witness; callbacks must only change a thread-safe validity flag. */
interface ISecureSpaceCredentialAttempt {
    boolean isActive();
    /** Synchronous revocation; never wait for the UI thread from this callback. */
    void invalidate();
}
