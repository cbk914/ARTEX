package sandboxbroker

import "regexp"

// A single delivery stays below the private tmpfs cap, leaving room for
// additional files and avoiding unbounded request buffering in the broker.
const maxArtifactBytes = 16 << 20

var artifactName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func validArtifactName(name string) bool {
	return name != "." && name != ".." && artifactName.MatchString(name)
}
