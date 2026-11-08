/*
 * Copyright (C) 2026 The Android Open Source Project
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

package com.android.systemui.keyguard.domain.interactor

import android.animation.ValueAnimator
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.systemui.SysuiTestCase
import com.android.systemui.bouncer.domain.interactor.PrimaryBouncerInteractor
import com.android.systemui.communal.domain.interactor.communalSceneInteractor
import com.android.systemui.communal.domain.interactor.communalSettingsInteractor
import com.android.systemui.flags.DisableSceneContainer
import com.android.systemui.keyguard.data.repository.fakeKeyguardTransitionRepository
import com.android.systemui.keyguard.shared.model.KeyguardState
import com.android.systemui.keyguard.shared.model.TransitionInfo
import com.android.systemui.keyguard.shared.model.TransitionState
import com.android.systemui.keyguard.shared.model.TransitionStep
import com.android.systemui.kosmos.applicationCoroutineScope
import com.android.systemui.kosmos.testDispatcher
import com.android.systemui.kosmos.testScope
import com.android.systemui.power.domain.interactor.powerInteractor
import com.android.systemui.shade.data.repository.fakeShadeRepository
import com.android.systemui.testKosmos
import com.android.systemui.util.mockito.mock
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers.anyBoolean
import org.mockito.ArgumentMatchers.anyFloat
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`

@SmallTest
@RunWith(AndroidJUnit4::class)
class FromLockscreenLegacyBouncerTest : SysuiTestCase() {
    private val kosmos = testKosmos()
    private val testScope = kosmos.testScope
    private val repository = kosmos.fakeKeyguardTransitionRepository
    private val shade = kosmos.fakeShadeRepository
    private val bouncer = mock<PrimaryBouncerInteractor>()
    private val showingSoon = MutableStateFlow(false)
    private val main = QueuedDispatcher()
    private lateinit var underTest: FromLockscreenTransitionInteractor

    @Before
    fun setUp() {
        `when`(bouncer.isShowing).thenReturn(MutableStateFlow(false))
        `when`(bouncer.isShowingSoon).thenReturn(showingSoon)
        underTest =
            FromLockscreenTransitionInteractor(
                transitionRepository = repository,
                internalTransitionInteractor = kosmos.internalKeyguardTransitionInteractor,
                transitionInteractor = kosmos.keyguardTransitionInteractor,
                scope = kosmos.applicationCoroutineScope,
                applicationScope = kosmos.applicationCoroutineScope,
                bgDispatcher = kosmos.testDispatcher,
                mainDispatcher = main,
                keyguardInteractor = kosmos.keyguardInteractor,
                shadeRepository = shade,
                powerInteractor = kosmos.powerInteractor,
                communalSettingsInteractor = kosmos.communalSettingsInteractor,
                communalSceneInteractor = kosmos.communalSceneInteractor,
                swipeToDismissInteractor = kosmos.swipeToDismissInteractor,
                keyguardOcclusionInteractor = kosmos.keyguardOcclusionInteractor,
                primaryBouncerInteractor = bouncer,
            )
    }

    @Test
    @DisableSceneContainer
    fun cancelledSwipe_doesNotReopenBouncerWhenMainThreadResumes() =
        testScope.runTest {
            queueRepair(0.5f)
            repository.currentTransitionInfo =
                TransitionInfo(
                    ownerName = "cancelled swipe",
                    from = KeyguardState.PRIMARY_BOUNCER,
                    to = KeyguardState.LOCKSCREEN,
                    animator = ValueAnimator(),
                )
            main.runAll()

            verify(bouncer, never()).show(anyBoolean(), anyString())
            verify(bouncer, never()).setPanelExpansion(anyFloat())
        }

    @Test
    @DisableSceneContainer
    fun returningSwipe_usesCurrentExpansionInsteadOfQueuedProgress() =
        testScope.runTest {
            queueRepair(0.4f)
            shade.setLegacyShadeExpansion(0.9f)
            main.runAll()

            verify(bouncer).setPanelExpansion(0.9f)
            verify(bouncer, never()).setPanelExpansion(0f)
        }

    @Test
    @DisableSceneContainer
    fun hiddenEndpoint_doesNotEnqueueShowBeforeCancellationTransitionStarts() =
        testScope.runTest {
            queueRepair(1f)
            main.runAll()

            verify(bouncer, never()).show(anyBoolean(), anyString())
            verify(bouncer).setPanelExpansion(1f)
        }

    @Test
    @DisableSceneContainer
    fun animatedBouncer_doesNotChangeItsExpansionOrScrimOwner() =
        testScope.runTest {
            queueRepair(1f)
            repository.currentTransitionInfo =
                repository.currentTransitionInfo.copy(animator = ValueAnimator())
            main.runAll()

            verify(bouncer, never()).show(anyBoolean(), anyString())
            verify(bouncer, never()).setPanelExpansion(anyFloat())
        }

    @Test
    @DisableSceneContainer
    fun invisibleLegacyBouncer_isStillRepairedDuringActiveManualTransition() =
        testScope.runTest {
            showingSoon.value = true
            queueRepair(0f)
            main.runAll()

            verify(bouncer)
                .show(
                    false,
                    "FromLockscreenTransitionInteractor#listenForLockscreenToPrimaryBouncerDragging",
                )
            verify(bouncer).setPanelExpansion(0f)
        }

    private suspend fun queueRepair(expansion: Float) {
        underTest.start()
        testScope.runCurrent()
        shade.setLegacyShadeExpansion(expansion)
        repository.sendTransitionStep(
            TransitionStep(
                from = KeyguardState.LOCKSCREEN,
                to = KeyguardState.PRIMARY_BOUNCER,
                value = 0f,
                transitionState = TransitionState.STARTED,
            )
        )
        // The collector accepts STARTED and suspends at the main-thread handoff. The test can
        // change the authoritative transition/expansion before allowing UI mutations to run.
        testScope.runCurrent()
    }

    private class QueuedDispatcher : CoroutineDispatcher() {
        private val queue = ArrayDeque<Runnable>()

        override fun dispatch(context: CoroutineContext, block: Runnable) {
            queue.addLast(block)
        }

        fun runAll() {
            while (queue.isNotEmpty()) queue.removeFirst().run()
        }
    }
}
