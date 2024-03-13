public struct LocalAuthenticationLocalizedStrings {
    let localizedReason: String
    let localisedFallbackTitle: String
    let localisedCancelTitle: String
    
    public init(localizedReason: String,
                localisedFallbackTitle: String,
                localisedCancelTitle: String) {
        self.localizedReason = localizedReason
        self.localisedFallbackTitle = localisedFallbackTitle
        self.localisedCancelTitle = localisedCancelTitle
    }
}
