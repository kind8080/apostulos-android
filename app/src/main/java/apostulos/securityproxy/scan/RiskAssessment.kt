package apostulos.securityproxy.scan

/**
 * Contextual triage helper for the local vulnerability catalogue.
 * The 0-100 value is an APOSTULOS prioritization aid, NOT CVSS and NOT a
 * prediction that a particular installed asset is vulnerable.
 */
object RiskAssessment {
    data class Result(
        val priority: String,
        val score: Int?,
        val explanation: String
    )

    fun assess(cvss: Double?, epss: Double?, knownExploited: Boolean): Result {
        val validCvss = cvss?.takeIf { it.isFinite() && it in 0.0..10.0 }
        val validEpss = epss?.takeIf { it.isFinite() && it in 0.0..1.0 }
        if (knownExploited) {
            return Result("URGENTE", score(validCvss, validEpss, true),
                "CVE consta no catálogo CISA KEV; confirme se o produto e a versão afetados existem no ativo.")
        }
        if (validCvss == null && validEpss == null) {
            return Result("INDETERMINADO", null,
                "Sem CVSS/EPSS disponíveis; consulte a fonte e confirme a aplicabilidade.")
        }
        val priority = when {
            validCvss != null && validCvss >= 9.0 -> "CRÍTICO"
            validCvss != null && validCvss >= 7.0 -> "ALTO"
            validCvss != null && validCvss >= 4.0 && (validEpss ?: 0.0) >= 0.5 -> "ALTO"
            validCvss != null && validCvss >= 4.0 -> "MODERADO"
            validEpss != null && validEpss >= 0.5 -> "ATENÇÃO"
            validEpss != null && validEpss >= 0.1 -> "ATENÇÃO"
            validCvss != null && validCvss > 0.0 -> "BAIXO"
            else -> "INDETERMINADO"
        }
        val explanation = buildList {
            if (validCvss != null) add("CVSS mede severidade técnica (${String.format(java.util.Locale.US, "%.1f", validCvss)}).")
            if (validEpss != null) add("EPSS estima probabilidade de exploração (${String.format(java.util.Locale.US, "%.2f%%", validEpss * 100)}).")
            add("A prioridade não confirma exposição; valide CPE, versão e configuração do ativo.")
        }.joinToString(" ")
        return Result(priority, score(validCvss, validEpss, false), explanation)
    }

    private fun score(cvss: Double?, epss: Double?, kev: Boolean): Int? {
        if (cvss == null && epss == null && !kev) return null
        val value = (cvss ?: 0.0) * 7.0 + (epss ?: 0.0) * 20.0 + if (kev) 20.0 else 0.0
        return value.toInt().coerceIn(0, 100)
    }
}
