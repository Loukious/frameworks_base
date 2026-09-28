/*
 * Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.systemui.authentication

import android.app.Application
import android.security.Flags
import com.android.internal.util.LatencyTracker
import com.android.internal.widget.LockscreenCredential
import com.android.systemui.authentication.data.repository.AuthenticationRepository
import com.android.systemui.authentication.data.repository.FakeAuthenticationRepository
import com.android.systemui.authentication.domain.interactor.AuthenticationInteractor
import com.android.systemui.authentication.shared.model.AuthenticationResult
import com.android.systemui.authentication.shared.model.AuthenticationResultModel
import com.android.systemui.user.domain.interactor.SelectedUserInteractor
import com.android.systemui.util.time.SystemClock
import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.MockedStatic
import org.mockito.Mockito.mockStatic
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], application = Application::class)
class SecureSpaceAuthenticationIdentityTest {
    private lateinit var flags: MockedStatic<Flags>
    private var selectedUserId = 0
    private val selectedUser: SelectedUserInteractor = mock()
    private val clock: SystemClock = mock()

    @Before
    fun setUp() {
        // These tests cover identity/lifecycle, not feature-flag configuration or second factors.
        flags = mockStatic(Flags::class.java)
        whenever(selectedUser.getSelectedUserId()).thenAnswer { selectedUserId }
    }

    @After
    fun tearDown() {
        flags.close()
    }

    private fun TestScope.interactor(
        repository: AuthenticationRepository
    ): AuthenticationInteractor {
        return AuthenticationInteractor(
            applicationScope = backgroundScope,
            backgroundDispatcher = StandardTestDispatcher(testScheduler),
            clock = clock,
            repository = repository,
            selectedUserInteractor = selectedUser,
            latencyTracker = mock<LatencyTracker>(),
        )
    }

    private fun AuthenticationInteractor.listen(results: MutableList<Boolean>) {
        addOnAuthenticationResultListener(
            object : AuthenticationInteractor.OnAuthenticationResultListener {
                override fun onAuthenticationResult(isSuccessful: Boolean) {
                    results += isSuccessful
                }
            }
        )
    }

    @Test
    fun successfulResultIdentifiesUser_failedResultDoesNot() {
        assertThat(AuthenticationResultModel(isSuccessful = true, checkedUserId = 10).matchedUserId)
            .isEqualTo(10)
        assertThat(
                AuthenticationResultModel(isSuccessful = false, checkedUserId = 10).matchedUserId
            )
            .isNull()
        assertThat(AuthenticationResultModel(isSuccessful = true).matchedUserId).isNull()
    }

    @Test
    fun normalCredential_notifiesOnceAndClearsCredential() = runTest {
        val repository = FakeAuthenticationRepository { currentTime }
        val interactor = interactor(repository)
        val results = mutableListOf<Boolean>()
        interactor.listen(results)

        assertThat(interactor.authenticate(FakeAuthenticationRepository.DEFAULT_PIN))
            .isEqualTo(AuthenticationResult.SUCCEEDED)
        assertThat(results).containsExactly(true)
        assertThat(repository.lastReportedUserId).isEqualTo(0)
        assertThrows(IllegalStateException::class.java) {
            repository.lastCheckedCredential!!.credential
        }
    }

    @Test
    fun mismatchedVerifierIdentity_failsClosedAndClearsCredential() = runTest {
        val delegate = FakeAuthenticationRepository { currentTime }
        var checkedCredential: LockscreenCredential? = null
        val repository =
            object : AuthenticationRepository by delegate {
                override suspend fun checkCredential(
                    credential: LockscreenCredential,
                    userId: Int,
                    onEarlyMatched: () -> Unit,
                ): AuthenticationResultModel {
                    checkedCredential = credential
                    return AuthenticationResultModel(isSuccessful = true, checkedUserId = 10)
                }
            }
        val interactor = interactor(repository)
        val results = mutableListOf<Boolean>()
        interactor.listen(results)
        try {
            interactor.authenticate(FakeAuthenticationRepository.DEFAULT_PIN)
            org.junit.Assert.fail("Mismatched identity must be rejected")
        } catch (expected: IllegalStateException) {
            assertThat(expected)
                .hasMessageThat()
                .isEqualTo("Credential result has a different user identity")
        }
        assertThat(results).isEmpty()
        assertThat(delegate.lastReportedUserId).isNull()
        assertThrows(IllegalStateException::class.java) { checkedCredential!!.credential }
    }

    @Test
    fun earlyMatch_doesNotDismissBeforeFullResult() = runTest {
        val repository = FakeAuthenticationRepository { currentTime }
        val fullResult = repository.deferFullSuccessResult()
        val interactor = interactor(repository)
        val results = mutableListOf<Boolean>()
        interactor.listen(results)
        val job = launch { interactor.authenticate(FakeAuthenticationRepository.DEFAULT_PIN) }
        runCurrent()
        assertThat(results).isEmpty()
        assertThat(job.isActive).isTrue()

        fullResult.complete(Unit)
        job.join()
        assertThat(results).containsExactly(true)
    }

    @Test
    fun selectedUserChanges_creditsOriginalUserAndDoesNotDismissNewUser() = runTest {
        val repository = FakeAuthenticationRepository { currentTime }
        val fullResult = repository.deferFullSuccessResult()
        val interactor = interactor(repository)
        val results = mutableListOf<Boolean>()
        interactor.listen(results)
        var result: AuthenticationResult? = null
        val job = launch {
            result = interactor.authenticate(FakeAuthenticationRepository.DEFAULT_PIN)
        }
        runCurrent()
        selectedUserId = 10
        fullResult.complete(Unit)
        job.join()

        assertThat(result).isEqualTo(AuthenticationResult.SKIPPED)
        assertThat(results).isEmpty()
        assertThat(repository.lastReportedUserId).isEqualTo(0)
        assertThrows(IllegalStateException::class.java) {
            repository.lastCheckedCredential!!.credential
        }
    }

    @Test
    fun cancellationAfterEarlyMatch_neverDismissesAndClearsCredential() = runTest {
        val repository = FakeAuthenticationRepository { currentTime }
        repository.deferFullSuccessResult()
        val interactor = interactor(repository)
        val results = mutableListOf<Boolean>()
        interactor.listen(results)
        val job = launch { interactor.authenticate(FakeAuthenticationRepository.DEFAULT_PIN) }
        runCurrent()
        job.cancel()
        job.join()

        assertThat(results).isEmpty()
        assertThat(repository.lastReportedUserId).isNull()
        assertThrows(IllegalStateException::class.java) {
            repository.lastCheckedCredential!!.credential
        }
    }

    @Test
    fun incorrectCredential_reportsFailureAndClearsCredential() = runTest {
        val repository = FakeAuthenticationRepository { currentTime }
        val interactor = interactor(repository)
        val results = mutableListOf<Boolean>()
        interactor.listen(results)
        assertThat(interactor.authenticate(FakeAuthenticationRepository.WRONG_PIN))
            .isEqualTo(AuthenticationResult.FAILED)
        assertThat(results).containsExactly(false)
        assertThat(repository.lastReportedUserId).isEqualTo(0)
        assertThrows(IllegalStateException::class.java) {
            repository.lastCheckedCredential!!.credential
        }
    }
    @Test
    fun routedNativeMatch_doesNotPublishGenericSuccessOrReportTwice() = runTest {
        val delegate = FakeAuthenticationRepository { currentTime }
        var checkedCredential: LockscreenCredential? = null
        val repository = object : AuthenticationRepository by delegate {
            override suspend fun checkCredential(
                credential: LockscreenCredential,
                userId: Int,
                onEarlyMatched: () -> Unit,
            ): AuthenticationResultModel {
                checkedCredential = credential
                return AuthenticationResultModel(checkedUserId = userId, isHandoffPending = true)
            }
        }
        val interactor = interactor(repository)
        val results = mutableListOf<Boolean>()
        interactor.listen(results)

        assertThat(interactor.authenticate(FakeAuthenticationRepository.DEFAULT_PIN))
            .isEqualTo(AuthenticationResult.HANDOFF_PENDING)
        assertThat(results).isEmpty()
        assertThat(delegate.lastReportedUserId).isNull()
        assertThrows(IllegalStateException::class.java) { checkedCredential!!.credential }
    }

    @Test
    fun inconclusiveRoutingResult_neverReportsWrongCredential() = runTest {
        val delegate = FakeAuthenticationRepository { currentTime }
        val repository = object : AuthenticationRepository by delegate {
            override suspend fun checkCredential(
                credential: LockscreenCredential,
                userId: Int,
                onEarlyMatched: () -> Unit,
            ) = AuthenticationResultModel(checkedUserId = userId, isInconclusive = true)
        }
        val interactor = interactor(repository)
        val results = mutableListOf<Boolean>()
        interactor.listen(results)
        assertThat(interactor.authenticate(FakeAuthenticationRepository.DEFAULT_PIN))
            .isEqualTo(AuthenticationResult.SKIPPED)
        assertThat(results).isEmpty()
        assertThat(delegate.lastReportedUserId).isNull()
    }

    @Test
    fun aggregateNativeRetry_startsCountdownWithoutPolicyFailure() = runTest {
        val delegate = FakeAuthenticationRepository { currentTime }
        var lockoutUser: Int? = null
        val retry = kotlin.time.Duration.parse("30s")
        val repository = object : AuthenticationRepository by delegate {
            override suspend fun checkCredential(
                credential: LockscreenCredential,
                userId: Int,
                onEarlyMatched: () -> Unit,
            ) = AuthenticationResultModel(checkedUserId = userId, isInconclusive = true,
                lockoutDuration = retry)
            override suspend fun reportLockoutStarted(
                duration: kotlin.time.Duration, userId: Int,
            ) { lockoutUser = userId }
        }
        val interactor = interactor(repository)
        val results = mutableListOf<Boolean>()
        interactor.listen(results)
        assertThat(interactor.authenticate(FakeAuthenticationRepository.DEFAULT_PIN))
            .isEqualTo(AuthenticationResult.FAILED)
        assertThat(results).containsExactly(false)
        assertThat(lockoutUser).isEqualTo(0)
        assertThat(delegate.lastReportedUserId).isNull()
    }

}
