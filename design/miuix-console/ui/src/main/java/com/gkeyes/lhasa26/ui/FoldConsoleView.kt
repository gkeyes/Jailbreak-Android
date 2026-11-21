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
    private var hardwareEffects by mutableStateOf(true)
    var listener: Listener? = null

    @MainThread
    fun render(state: FoldUiState) {
        snapshot = state
    }

    @MainThread
    fun setBrandName(name: String) {
        displayName = name
    }

    /** Disable before composing content intended for a software Canvas, e.g. a bitmap export. */
    @MainThread
    fun setHardwareEffectsEnabled(enabled: Boolean) {
        hardwareEffects = enabled
    }

    /** Java-friendly sink: the generated property setter is not visible to the app module. */
    @MainThread
    fun attachListener(sink: Listener?) {
        listener = sink
    }

    @Composable
    override fun Content() {
        FoldConsole(state = snapshot, onEvent = { listener?.onEvent(it) }, brandName = displayName,
            hardwareEffectsEnabled = hardwareEffects)
    }
}
