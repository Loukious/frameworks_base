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

package com.android.systemui.common.ui.view

import android.view.View
import android.widget.FrameLayout
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.internal.graphics.drawable.BackgroundBlurDrawable
import com.android.systemui.SysuiTestCase
import com.android.systemui.util.mockito.mock
import com.android.systemui.util.mockito.whenever
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito.verify

@SmallTest
@RunWith(AndroidJUnit4::class)
class BackgroundBlurAlphaSyncTest : SysuiTestCase() {
    private val view: View = mock()
    private val parent: FrameLayout = mock()
    private val blur: BackgroundBlurDrawable = mock()
    private val sync = BackgroundBlurAlphaSync(view) { blur }

    @Test
    fun sync_multipliesViewAndAncestorAlphas() {
        whenever(view.alpha).thenReturn(0.5f)
        whenever(view.transitionAlpha).thenReturn(1f)
        whenever(view.parent).thenReturn(parent)
        whenever(parent.alpha).thenReturn(0.5f)
        whenever(parent.transitionAlpha).thenReturn(0.5f)

        sync.sync()

        verify(blur).setAlpha(32)
    }

    @Test
    fun sync_invalidAncestorAlpha_hidesBlurThenRecovers() {
        whenever(view.alpha).thenReturn(1f)
        whenever(view.transitionAlpha).thenReturn(1f)
        whenever(view.parent).thenReturn(parent)
        whenever(parent.alpha).thenReturn(Float.NaN)
        whenever(parent.transitionAlpha).thenReturn(1f)
        whenever(blur.alpha).thenReturn(255)

        sync.sync()
        verify(blur).setAlpha(0)

        whenever(parent.alpha).thenReturn(0.5f)
        sync.sync()
        verify(blur).setAlpha(128)
    }

    @Test
    fun sync_invalidTransitionAlpha_hidesBlur() {
        whenever(view.alpha).thenReturn(1f)
        whenever(view.transitionAlpha).thenReturn(Float.POSITIVE_INFINITY)
        whenever(blur.alpha).thenReturn(255)

        sync.sync()

        verify(blur).setAlpha(0)
    }
}
