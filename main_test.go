package main

import "testing"

func TestAssetVersion(t *testing.T) {
	const sha = "82be87d9e867edaa2ed3b562cd40cc685c787861"
	for _, tc := range []struct{ name, version, commit, want string }{
		{"untagged build gets the short commit", "dev", sha, "dev-82be87d"},
		{"tagged release keeps its tag", "v1.2.3", sha, "v1.2.3"},
		{"local build without a commit", "dev", "unknown", "dev"},
		{"commit too short to trust", "dev", "abc", "dev"},
	} {
		if got := assetVersion(tc.version, tc.commit); got != tc.want {
			t.Errorf("%s: assetVersion(%q, %q) = %q, want %q", tc.name, tc.version, tc.commit, got, tc.want)
		}
	}
}
