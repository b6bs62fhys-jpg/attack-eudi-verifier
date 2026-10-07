package de.eudi.verify.sdk

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Java-tauglicher Zugriff auf die JSON-Bausteine des Clients.
 *
 * In Kotlin sind `JsonPrimitive` und `Json.parseToJsonElement` top-Level-
 * Funktionen und aus Java nur ueber umstaendliche Namen erreichbar. Diese
 * Fassung legt sie als statische Methoden ab, damit eine Java-Anwendung
 * eine `vp_token`-Huelle ohne Zusatzabhaengigkeit bauen kann.
 */
public object AttackJson {
    /** JSON-Zeichenkette, zum Beispiel eine SD-JWT. */
    @JvmStatic
    public fun string(value: String): JsonElement = JsonPrimitive(value)

    /** JSON-Objekt aus geraden Schluessel-Wert-Paaren. */
    @JvmStatic
    public fun obj(vararg pairs: Pair<String, JsonElement>): JsonObject = JsonObject(pairs.toMap())

    /** JSON-Array aus beliebigen Elementen. */
    @JvmStatic
    public fun array(vararg elements: JsonElement): JsonArray = JsonArray(elements.toList())

    /** Beliebiges JSON-Element aus Text. */
    @JvmStatic
    public fun parse(text: String): JsonElement = AttackClient.defaultJson().parseToJsonElement(text)

    /** JSON-Objekt aus Text; wirft, wenn der Text kein Objekt ist. */
    @JvmStatic
    public fun parseObject(text: String): JsonObject = parse(text) as JsonObject
}
