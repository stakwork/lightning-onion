package sphinx

import (
	"errors"

	"github.com/btcsuite/btcd/btcec"
)

// ProcessOnionPacketWithExternal uses an external key
func (r *Router) ProcessOnionPacketWithExternal(
	onionPkt *OnionPacket,
	assocData []byte,
	incomingCltv uint32,
	sharedSecretGenerator func(dhKey *btcec.PublicKey) (Hash256, error),
) (*ProcessedPacket, error) {

	if sharedSecretGenerator == nil {
		return nil, errors.New("no sharedSecretGenerator")
	}

	// Compute the shared secret for this onion packet.
	sharedSecret, err := sharedSecretGenerator(onionPkt.EphemeralKey)
	if err != nil {
		return nil, err
	}

	// Additionally, compute the hash prefix of the shared secret, which
	// will serve as an identifier for detecting replayed packets.
	hashPrefix := hashSharedSecret(&sharedSecret)

	// Continue to optimistically process this packet, deferring replay
	// protection until the end to reduce the penalty of multiple IO
	// operations.
	packet, err := processOnionPacket(onionPkt, &sharedSecret, assocData, r)
	if err != nil {
		return nil, err
	}

	// Atomically compare this hash prefix with the contents of the on-disk
	// log, persisting it only if this entry was not detected as a replay.
	if err := r.log.Put(hashPrefix, incomingCltv); err != nil {
		return nil, err
	}

	return packet, nil
}
