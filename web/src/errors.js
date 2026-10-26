// =============================================================================
// SealKeeper — Generation errors
// =============================================================================
// PRD A §7. Shared by the generators, the entropy calculator and the entry
// point so every layer fails with the same typed error.
// =============================================================================

/**
 * The policy descriptor (or one of its parameters) is malformed. Extends
 * TypeError so callers that historically caught a TypeError from
 * calculateEntropy keep working.
 */
export class InvalidPolicyDescriptor extends TypeError {
  constructor(msg) {
    super(`InvalidPolicyDescriptor: ${msg}`);
    this.name = "InvalidPolicyDescriptor";
  }
}

/** G1/G2 policy without a usable inline library (PRD A §7). */
export class LibraryNotFound extends Error {
  constructor(msg) {
    super(`LibraryNotFound: ${msg}`);
    this.name = "LibraryNotFound";
  }
}

export class RegenerationLimitExceeded extends Error {
  constructor() {
    super("RegenerationLimitExceeded");
    this.name = "RegenerationLimitExceeded";
  }
}
