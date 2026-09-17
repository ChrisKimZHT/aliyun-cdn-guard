package model

type AccessEvent struct {
	EventID   string
	Timestamp int64
	Domain    string
	ClientIP  string
	UserAgent string
	URI       string
	URIParam  string
}

type BlockDecision struct {
	Domain       string
	ClientIP     string
	Count        int
	BlockedUntil int64
	OffenseCount int
	BlockedAt    int64
}

type BlockRecord struct {
	Domain       string
	ClientIP     string
	BlockedUntil int64
	OffenseCount int
	CDNOwned     *bool
}
