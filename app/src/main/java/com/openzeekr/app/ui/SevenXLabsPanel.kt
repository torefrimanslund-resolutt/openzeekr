package com.openzeekr.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.openzeekr.app.Deps
import com.openzeekr.app.remote.*
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

/** Screen-owned memory: scrolling the lazy list must not discard the baseline. */
internal class LabsPanelState {
    var baseline by mutableStateOf<LabsSnapshot?>(null)
    var current by mutableStateOf<LabsSnapshot?>(null)
    var error by mutableStateOf<String?>(null)
    var busy by mutableStateOf(false)
    var expanded by mutableStateOf(false)
    var showRaw by mutableStateOf(false)
    var job: Job? = null
    var generation = 0

    fun clear() {
        generation++
        job?.cancel(); job = null; busy = false
        baseline = null; current = null; error = null; expanded = false; showRaw = false
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun SevenXLabsPanel(deps: Deps, state: LabsPanelState, scope: kotlinx.coroutines.CoroutineScope) = with(state) {
    fun capture(asBaseline: Boolean) {
        if (busy) return
        busy = true
        error = null
        val captureGeneration = ++generation
        job = scope.launch {
            try {
                when (val result = deps.control.labsSnapshot()) {
                    is CallResult.Err -> error = result.message
                    is CallResult.Ok -> {
                        if (result.value.sources.values.all { it.raw == null }) {
                            error = "All three reads failed. Previous snapshots kept; check connection and sign-in."
                        } else if (asBaseline) {
                            baseline = result.value
                            current = null
                        } else current = result.value
                    }
                }
            } finally { if (generation == captureGeneration) busy = false }
        }
    }

    val changes = remember(baseline, current) {
        baseline?.let { before -> current?.let { LabsJson.compare(before, it) } }.orEmpty()
    }
    val latest = current ?: baseline
    fun time(snapshot: LabsSnapshot) = DateFormat.getTimeInstance().format(Date(snapshot.capturedAt))

    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("7X Labs", style = MaterialTheme.typography.titleMedium)
            Text("Read-only research: capture a baseline, toggle one feature manually in the vehicle, then compare.",
                style = MaterialTheme.typography.bodySmall)
            Text("Cloud snapshots may be cached; capture time is not vehicle update time. No commands or service-ID probes are sent.",
                style = MaterialTheme.typography.bodySmall)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { capture(true) }, enabled = !busy) { Text("Baseline") }
                TextButton(onClick = { capture(false) }, enabled = !busy && baseline != null) { Text("Compare now") }
                TextButton(onClick = {
                    clear()
                }) { Text("Clear") }
            }
            if (busy) Text("Reading three cloud snapshots…")
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            baseline?.let { Text("Baseline: ${time(it)}") }
            current?.let { Text("Compared: ${time(it)} · ${changes.size} changes in readable sources") }
            listOfNotNull(baseline?.let { "Baseline" to it }, current?.let { "Compare" to it }).forEach { (label, snapshot) ->
                snapshot.sources.forEach { (source, result) ->
                    result.error?.let { Text("$label · $source: $it (not compared)", color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall) }
                }
            }
            latest?.let { snapshot ->
                LabsJson.modeFields.forEach { field ->
                    val matches = snapshot.values.filterKeys { it.substringAfterLast('/') == field }
                    if (matches.isEmpty()) Text("$field: not present in readable data", style = MaterialTheme.typography.bodySmall)
                    else matches.forEach { (path, value) -> Text("$path = $value", fontWeight = FontWeight.SemiBold) }
                }
            }
            changes.forEach { change ->
                val research = LabsJson.researchRelated(change.path)
                Text("${if (research) "Research · " else ""}${change.kind}: ${change.path}\n" +
                    "${change.before ?: "[absent]"} → ${change.after ?: "[absent]"}",
                    color = if (research) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                    fontWeight = if (research) FontWeight.Bold else FontWeight.Normal,
                    style = MaterialTheme.typography.bodySmall)
            }
            if (current != null && changes.isEmpty()) Text("No changes detected in sources readable in both snapshots.")
            if (latest != null) {
                TextButton(onClick = { expanded = !expanded }) { Text(if (expanded) "Hide snapshot" else "Show sanitized snapshot") }
                if (expanded) {
                    TextButton(onClick = { showRaw = !showRaw }) { Text(if (showRaw) "Show key/value pairs" else "Show raw JSON (sanitized)") }
                    if (showRaw) latest.sources.forEach { (name, source) ->
                        source.raw?.let { Text("$name\n$it", style = MaterialTheme.typography.bodySmall) }
                    } else latest.values.toSortedMap().forEach { (path, value) ->
                        Text("$path = $value", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            Text("Sensitive fields are filtered. Snapshots stay in memory until Clear or leaving Controls. " +
                "PCM is a Parking Comfort research lead only; Camp Mode, cabin-light and direct fan-speed commands are unverified.",
                style = MaterialTheme.typography.bodySmall)
        }
    }
}
