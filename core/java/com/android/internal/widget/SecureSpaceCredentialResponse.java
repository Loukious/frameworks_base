/*
 * Copyright (C) 2026 The Android Open Source Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.internal.widget;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.UserHandle;

/**
 * Completed concealed-entry attempt, for trusted keyguard callers only. Contains no credential,
 * hardware authentication token, or synthetic-password handle. A match authorizes neither a
 * user switch nor keyguard dismissal without a separate foreground/serial/lifecycle check.
 *
 * @hide
 */
public final class SecureSpaceCredentialResponse implements Parcelable {
    public static final int MATCHED = 1;
    public static final int INCORRECT = 2;
    public static final int INCONCLUSIVE = 3;
    public static final int STALE = 4;

    private final IBinder mHandoffToken;
    private boolean mErasurePending;
    private final int mMatchedUserId;
    private final int mMatchedSerialNumber;
    private final boolean mAllCertainlyIncorrect;
    private final int[] mUserIds;
    private final int[] mSerialNumbers;
    private final int[] mOutcomes;
    private final long[] mTimeoutMillis;
    private final boolean[] mDuplicates;

    public SecureSpaceCredentialResponse(int matchedUserId, int matchedSerialNumber,
            boolean allCertainlyIncorrect, int[] userIds, int[] serialNumbers, int[] outcomes,
            long[] timeoutMillis, boolean[] duplicates, IBinder handoffToken) {
        int length = userIds.length;
        if (serialNumbers.length != length || outcomes.length != length
                || timeoutMillis.length != length || duplicates.length != length) {
            throw new IllegalArgumentException("Inconsistent routing response");
        }
        mHandoffToken = handoffToken;
        mMatchedUserId = matchedUserId;
        mMatchedSerialNumber = matchedSerialNumber;
        mAllCertainlyIncorrect = allCertainlyIncorrect;
        mUserIds = userIds.clone();
        mSerialNumbers = serialNumbers.clone();
        mOutcomes = outcomes.clone();
        mTimeoutMillis = timeoutMillis.clone();
        mDuplicates = duplicates.clone();
    }

    public static SecureSpaceCredentialResponse unavailable() {
        return new SecureSpaceCredentialResponse(UserHandle.USER_NULL, -1, false,
                new int[0], new int[0], new int[0], new long[0], new boolean[0], null);
    }

    public static SecureSpaceCredentialResponse erasurePending() {
        SecureSpaceCredentialResponse response = unavailable();
        response.mErasurePending = true;
        return response;
    }

    public boolean isErasurePending() { return mErasurePending; }

    public IBinder getHandoffToken() { return mHandoffToken; }
    public int getMatchedUserId() { return mMatchedUserId; }
    public int getMatchedSerialNumber() { return mMatchedSerialNumber; }
    public boolean isAllCertainlyIncorrect() { return mAllCertainlyIncorrect; }
    public int[] getUserIds() { return mUserIds.clone(); }
    public int[] getSerialNumbers() { return mSerialNumbers.clone(); }
    public int[] getOutcomes() { return mOutcomes.clone(); }
    public long[] getTimeoutMillis() { return mTimeoutMillis.clone(); }
    public boolean[] getDuplicates() { return mDuplicates.clone(); }

    @Override
    public int describeContents() { return 0; }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(mMatchedUserId);
        dest.writeInt(mMatchedSerialNumber);
        dest.writeBoolean(mAllCertainlyIncorrect);
        dest.writeIntArray(mUserIds);
        dest.writeIntArray(mSerialNumbers);
        dest.writeIntArray(mOutcomes);
        dest.writeLongArray(mTimeoutMillis);
        dest.writeBooleanArray(mDuplicates);
        dest.writeStrongBinder(mHandoffToken);
        dest.writeBoolean(mErasurePending);
    }

    public static final Creator<SecureSpaceCredentialResponse> CREATOR = new Creator<>() {
        @Override
        public SecureSpaceCredentialResponse createFromParcel(Parcel source) {
            SecureSpaceCredentialResponse response = new SecureSpaceCredentialResponse(source.readInt(), source.readInt(),
                    source.readBoolean(), source.createIntArray(), source.createIntArray(),
                    source.createIntArray(), source.createLongArray(), source.createBooleanArray(), source.readStrongBinder());
            response.mErasurePending = source.readBoolean();
            return response;
        }

        @Override
        public SecureSpaceCredentialResponse[] newArray(int size) {
            return new SecureSpaceCredentialResponse[size];
        }
    };
}
