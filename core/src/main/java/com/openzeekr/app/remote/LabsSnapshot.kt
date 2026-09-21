package com.openzeekr.app.remote

import kotlinx.serialization.json.*

/** Only sanitized response data may be retained in Labs state. Never persisted or logged. */
data class LabsSnapshot(val capturedAt: Long, val sources: Map<String, LabsSource>) {
    val values: Map<String, String> get() = sources.flatMap { (source, result) ->
        result.values.map { (key, value) -> "$source$key" to value }
    }.toMap()
}

data class LabsSource(val raw: JsonElement? = null, val error: String? = null) {
    val values: Map<String, String> get() = raw?.let(LabsJson::flatten).orEmpty()
}

data class LabsChange(val path: String, val before: String?, val after: String?) {
    val kind: String get() = when { before == null -> "Added"; after == null -> "Removed"; else -> "Changed" }
}

object LabsJson {
    private fun normalized(key: String) = key.lowercase().filter { it.isLetterOrDigit() }
    private val sensitive = listOf("vin", "latitude", "longitude", "coordinate", "position", "location",
        "userid", "useridentifier", "deviceid", "deviceidentifier", "account", "owner", "customer",
        "token", "secret", "password", "session", "email", "phone", "address", "uuid", "imei", "imsi",
        "serialnumber", "plate", "registration", "openid", "unionid", "clientid", "instanceid",
        "user", "device", "gps", "geohash", "macaddress", "vehicleidentification", "chassisnumber")
    private fun privateKey(key: String): Boolean {
        val k = normalized(key)
        // Avoid matching drivingSafetyStatus as VIN. Unknown identifiers are omitted conservatively.
        return k == "vin" || k.startsWith("vin") || k.endsWith("vin") ||
            k.endsWith("id") || k.endsWith("identifier") ||
            k.endsWith("lat") || k.endsWith("lon") || k.endsWith("lng") ||
            k in setOf("lat", "lon", "lng", "gps", "mac", "sn", "uid", "did") ||
            sensitive.drop(1).any { it in k }
    }

    /** Redact entire sensitive subtrees, including key/value descriptor records and JSON strings. */
    fun sanitize(element: JsonElement, knownSecrets: List<String> = emptyList()): JsonElement {
        val secrets = knownSecrets.filter { it.isNotBlank() }
        fun secretText(value: String) = secrets.any { value.contains(it, ignoreCase = true) } ||
            Regex("(?i)\\b[A-HJ-NPR-Z0-9]{17}\\b").containsMatchIn(value) ||
            Regex("(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}").containsMatchIn(value) ||
            Regex("(?i)\\b[0-9a-f]{8}-[0-9a-f-]{27,}\\b").containsMatchIn(value)
        fun clean(value: JsonElement): JsonElement = when (value) {
            is JsonObject -> {
                val descriptor = value.any { (label, field) ->
                    normalized(label) in listOf("key", "name", "field", "property", "fieldname", "propertyname") &&
                        (field as? JsonPrimitive)?.content?.let(::privateKey) == true
                }
                if (descriptor) JsonPrimitive("[redacted]") else JsonObject(value.mapNotNull { (k, v) ->
                    if (privateKey(k) || secretText(k)) null else k to clean(v)
                }.toMap())
            }
            is JsonArray -> JsonArray(value.map(::clean))
            is JsonPrimitive -> if (value.isString) {
                val content = value.content
                val embedded = if (content.trimStart().startsWith("{") || content.trimStart().startsWith("["))
                    runCatching { Json.parseToJsonElement(content) }.getOrNull() else null
                when {
                    embedded != null -> JsonPrimitive(clean(embedded).toString())
                    secretText(content) -> JsonPrimitive("[redacted]")
                    else -> value
                }
            } else value
        }
        return clean(element)
    }

    /** JSON Pointer paths escape separators, preserving arrays, nulls and primitive types. */
    fun flatten(element: JsonElement): Map<String, String> = buildMap {
        fun visit(value: JsonElement, path: String) {
            when (value) {
                is JsonObject -> if (value.isEmpty()) put(path, "{}") else value.forEach { (k, v) ->
                    visit(v, "$path/${k.replace("~", "~0").replace("/", "~1")}")
                }
                is JsonArray -> if (value.isEmpty()) put(path, "[]") else value.forEachIndexed { i, v -> visit(v, "$path/$i") }
                else -> put(path, value.toString())
            }
        }
        visit(element, "")
    }

    /** Failed sources are never interpreted as removed data. */
    fun compare(baseline: LabsSnapshot, current: LabsSnapshot): List<LabsChange> =
        baseline.sources.keys.intersect(current.sources.keys).flatMap { source ->
            val old = baseline.sources.getValue(source)
            val new = current.sources.getValue(source)
            if (old.raw == null || new.raw == null) emptyList() else {
                val before = old.values
                val after = new.values
                (before.keys + after.keys).sorted().mapNotNull { key ->
                    if (before[key] == after[key]) null else LabsChange("$source$key", before[key], after[key])
                }
            }
        }.sortedWith(compareByDescending<LabsChange> { researchRelated(it.path) }.thenBy { it.path })

    fun researchRelated(path: String): Boolean = listOf("camp", "parkingcomfort", "cabinlight", "interiorlight",
        "ambientlight", "airflow", "fanspeed", "blower", "vent", "climate", "overheat", "washcar", "pcm")
        .any { it in normalized(path) }

    val modeFields = listOf("campingModeState", "parkingComfortState", "overheatState", "washCarModeState")
}
