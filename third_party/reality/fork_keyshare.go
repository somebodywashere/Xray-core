package reality

func classicX25519KeyShare(hello *clientHelloMsg) []byte {
	for _, group := range hello.supportedCurves {
		if group == X25519MLKEM768 {
			return nil
		}
	}

	var share []byte

	for _, ks := range hello.keyShares {
		switch ks.group {
		case X25519MLKEM768:
			return nil
		case X25519:
			if share != nil || len(ks.data) != 32 {
				return nil
			}
			share = ks.data
		}
	}

	return share
}
