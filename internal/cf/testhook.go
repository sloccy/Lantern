package cf

// SetBaseURLForTest points the Cloudflare API client at a fake server for the
// duration of a test in another package. It restores the original URL on cleanup.
func SetBaseURLForTest(t interface{ Cleanup(func()) }, url string) {
	orig := cfBaseURL
	cfBaseURL = url
	t.Cleanup(func() { cfBaseURL = orig })
}
