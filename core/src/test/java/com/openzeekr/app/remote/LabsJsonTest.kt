package com.openzeekr.app.remote

import kotlinx.serialization.json.Json
import org.junit.Assert.*
import org.junit.Test

class LabsJsonTest {
    private fun parse(text: String) = Json.parseToJsonElement(text)
    private fun snapshot(vararg sources: Pair<String, LabsSource>) = LabsSnapshot(0, sources.toMap())

    @Test fun sensitiveSubtreesAndDescriptorValuesAreRemovedBeforeFlattening() {
        val raw = parse("""{
          "VIN":"TESTVIN12345678901", "Latitude":59.91, "longitude":10.75,
          "user":{"name":"Private Person","id":12}, "deviceIdentifier":"private-device",
          "nested":[{"key":"user_id","value":"private-user"},{"campingModeState":"1"}],
          "encoded":"{\"latitude\":59.91,\"parkingComfortState\":1}",
          "echo":"private-device", "drivingSafetyStatus":{"centralLockingStatus":"1"}
        }""")
        val safe = LabsJson.sanitize(raw, listOf("private-device")).toString()
        listOf("TESTVIN", "59.91", "10.75", "Private Person", "private-device", "private-user").forEach {
            assertFalse("Leaked $it", safe.contains(it))
        }
        assertTrue(safe.contains("campingModeState"))
        assertTrue(safe.contains("parkingComfortState"))
        assertTrue(safe.contains("drivingSafetyStatus"))
    }

    @Test fun flattenPreservesTypesNullsEmptyContainersAndEscapesPaths() {
        val flat = LabsJson.flatten(parse("""{"a/b":[null,"1",1,true,{},[]],"a":{"b":2},"~":false}"""))
        assertEquals("null", flat["/a~1b/0"])
        assertEquals("\"1\"", flat["/a~1b/1"])
        assertEquals("1", flat["/a~1b/2"])
        assertEquals("true", flat["/a~1b/3"])
        assertEquals("{}", flat["/a~1b/4"])
        assertEquals("[]", flat["/a~1b/5"])
        assertEquals("2", flat["/a/b"])
        assertEquals("false", flat["/~0"])
    }

    @Test fun compareDistinguishesAddedRemovedNullAndResearchChanges() {
        val before = snapshot("state" to LabsSource(parse("""{"campingModeState":0,"old":null,"same":1}""")))
        val after = snapshot("state" to LabsSource(parse("""{"campingModeState":1,"new":null,"same":1}""")))
        val changes = LabsJson.compare(before, after)
        assertEquals(3, changes.size)
        assertEquals("state/campingModeState", changes.first().path)
        assertEquals("Changed", changes.first().kind)
        assertEquals("Added", changes.single { it.path == "state/new" }.kind)
        assertEquals("Removed", changes.single { it.path == "state/old" }.kind)
        assertTrue(LabsJson.compare(before, before).isEmpty())
    }

    @Test fun failedSourcesDoNotProduceFalseRemovalsOrAdditions() {
        val good = snapshot("status" to LabsSource(parse("""{"airflow":2}""")))
        val failed = snapshot("status" to LabsSource(error = "Read failed"))
        assertTrue(LabsJson.compare(good, failed).isEmpty())
        assertTrue(LabsJson.compare(failed, good).isEmpty())
    }

    @Test fun highlightsResearchFieldsWithoutInterpretingTheirValues() {
        listOf("campingModeState", "parkingComfortState", "overheatState", "washCarModeState",
            "cabin_lights", "interiorLight", "airFlow", "fanSpeed", "blower", "PCM").forEach {
            assertTrue(it, LabsJson.researchRelated(it))
        }
        assertFalse(LabsJson.researchRelated("odometer"))
    }
}
