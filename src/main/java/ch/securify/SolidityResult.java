package ch.securify;

import ch.securify.analysis.SecurifyErrors;
import ch.securify.patterns.AbstractPattern;
import ch.securify.patterns.PatternDescription;

import java.util.LinkedList;
import java.util.List;
import java.util.TreeMap;

class SolidityResult {
    private static String securifyVersion = null;
    String version;

    static void setSecurifyVersion(String secVersion) {
        if (securifyVersion != null ) {
            throw new RuntimeException("Securify version is already specified.");
        }
        securifyVersion = secVersion;
    }

    SolidityResult(SecurifyErrors securifyErrors) {
        if (securifyVersion == null ) {
            throw new RuntimeException("Securify version unspecified.");
        }

        this.version = securifyVersion;
        this.securifyErrors = securifyErrors;
    }

    /**
     * Add the descriptions of all the patterns
     *
     * @param patterns: all the patterns considered in this Securify version
     */
    static void setPatternDescriptions(List<AbstractPattern> patterns) {
        // only allow initialization once
        patternDescriptions = new LinkedList<>();
        patterns.forEach(pattern -> patternDescriptions.add(pattern.getDescription()));
    }

    public static List<PatternDescription> patternDescriptions;

    TreeMap<String, SmallPatternResult> results = new TreeMap<>();

    SecurifyErrors securifyErrors;
}
