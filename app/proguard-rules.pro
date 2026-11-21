# Shizuku is reached through reflection: ShizukuExecutor looks up Shizuku.newProcess by name.
-keep class rikka.shizuku.** { *; }
-keep class moe.shizuku.** { *; }
-keepclassmembers class rikka.shizuku.Shizuku {
    private static ** newProcess(...);
}

# The console state is built from Java with a positional constructor.
-keep class com.gkeyes.lhasa26.ui.FoldUiState { *; }
-keep class com.gkeyes.lhasa26.ui.FoldEvent { *; }
-keep class com.gkeyes.lhasa26.ui.FoldConsoleView { *; }
-keep interface com.gkeyes.lhasa26.ui.FoldConsoleView$Listener { *; }

# Activities/providers named in the manifest keep themselves via AGP, but keep them explicit.
-keep class com.gkeyes.lhasa26.ConsoleActivity { *; }
-keep class com.gkeyes.lhasa26.MainActivity { *; }

-dontwarn rikka.shizuku.**
-dontwarn moe.shizuku.**
