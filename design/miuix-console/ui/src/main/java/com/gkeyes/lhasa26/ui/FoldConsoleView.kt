package com.gkeyes.lhasa26.ui

import android.content.Context
import android.util.AttributeSet
import androidx.annotation.MainThread
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.AbstractComposeView

/** View-system entry point for a host with AndroidX lifecycle and saved-state owners. */
class FoldConsoleView @JvmOverloads constructor(
    context: Context, attrs: AttributeSet? = null,
) : AbstractComposeView(context, attrs) {

    fun interface Listener {
        fun onEvent(event: FoldEvent)
    }

    private var snapshot by mutableStateOf(FoldUiState())
    private var displayName by mutableStateOf("18fold越狱")
    var listener: Listener? = null

    @MainThread
    fun render(state: FoldUiState) {
        snapshot = state
    }

    @MainThread
    fun setBrandName(name: String) {
        displayName = name
    }

    @Composable
    override fun Content() {
        FoldConsole(state = snapshot, onEvent = { listener?.onEvent(it) }, brandName = displayName)
    }
}
