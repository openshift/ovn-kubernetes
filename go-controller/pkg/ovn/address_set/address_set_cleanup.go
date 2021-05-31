package addressset

// NonDualStackAddressSetCleanup cleans addresses in old non dual stack format.
// Assumes that for every address set <name>, if there exists an address set
// of <name_[v4|v6]>, address set <name> is no longer used and removes it.
// This method should only be called after ensuring address sets in old format
// are no longer being referenced from any other object.
func NonDualStackAddressSetCleanup() error {
	// For each address set, track if it is in old non dual stack
	// format and in new dual stack format
	addressSets := map[string][2]bool{}
	err := forEachAddressSet(func(name string) {
		shortName := truncateSuffixFromAddressSet(name)
		info, found := addressSets[shortName]
		if !found {
			info = [2]bool{false, false}
		}
		if shortName == name {
			// This address set is in old non dual stack format
			info[0] = true
		} else {
			// This address set is in new dual stack format
			info[1] = true
		}
		addressSets[shortName] = info
	})
	if err != nil {
		return err
	}

	for name, info := range addressSets {
		// If we have an address set in both old and new formats,
		// we can safely remove the old format.
		if info[0] && info[1] {
			err := destroyAddressSet(name)
			if err != nil {
				return err
			}
		}
	}

	return nil
}