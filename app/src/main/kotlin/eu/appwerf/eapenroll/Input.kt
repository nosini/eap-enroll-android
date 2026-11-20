package eu.appwerf.eapenroll

object Input {
    private val label = Regex("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")

    /**
     * Returns [text] as a lower-case host name without whitespace or a
     * trailing dot, or throws if it isn't a valid host name.
     */
    fun normalizeDomain(text: String): String {
        val domain = text.filterNot { it.isWhitespace() }.lowercase().removeSuffix(".")
        require(domain.isNotEmpty() && domain.length <= 253) { "Invalid server domain '$text'" }
        require(domain.split('.').all { label.matches(it) }) { "Invalid server domain '$text'" }
        return domain
    }
}
