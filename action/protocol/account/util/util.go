// Copyright (c) 2018 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package accountutil

import (
	"math/big"

	"github.com/pkg/errors"

	"github.com/iotexproject/go-pkgs/hash"
	"github.com/iotexproject/iotex-address/address"

	"github.com/iotexproject/iotex-core/action/protocol"
	"github.com/iotexproject/iotex-core/state"
)

// AccountCreationOption is to create new account with specific settings
type AccountCreationOption func(*state.Account) error

// ZeroNonceAccountTypeOption is an option to create account with new account type
func ZeroNonceAccountTypeOption() AccountCreationOption {
	return func(account *state.Account) error {
		account.Type = 1
		return nil
	}
}

// SetNonce sets nonce for account
func SetNonce(state *state.Account, nonce uint64) error {
	if nonce == state.PendingNonce() {
		state.SetNonce(nonce)
		return nil
	}
	if nonce != 0 { // for system actions
		return errors.Errorf("invalid nonce %d, expect %d", nonce, state.PendingNonce())
	}

	return nil
}

// LoadOrCreateAccount either loads an account state or creates an account state
func LoadOrCreateAccount(sm protocol.StateManager, addr address.Address, opts ...AccountCreationOption) (*state.Account, error) {
	var (
		account  state.Account
		addrHash = hash.BytesToHash160(addr.Bytes())
	)
	_, err := sm.State(&account, protocol.LegacyKeyOption(addrHash))
	if err == nil {
		return &account, nil
	}
	if errors.Cause(err) == state.ErrStateNotExist {
		account.Balance = big.NewInt(0)
		account.VotingWeight = big.NewInt(0)
		for _, opt := range opts {
			if err := opt(&account); err != nil {
				return nil, errors.Wrap(err, "failed to apply account creation option")
			}
		}
		if _, err := sm.PutState(account, protocol.LegacyKeyOption(addrHash)); err != nil {
			return nil, errors.Wrapf(err, "failed to put state for account %x", addrHash)
		}
		return &account, nil
	}
	return nil, err
}

// LoadAccount loads an account state by address.Address
func LoadAccount(sr protocol.StateReader, addr address.Address) (*state.Account, error) {
	return LoadAccountByHash160(sr, hash.BytesToHash160(addr.Bytes()))
}

// LoadAccountByHash160 loads an account state by 20-byte address
func LoadAccountByHash160(sr protocol.StateReader, addrHash hash.Hash160) (*state.Account, error) {
	var account state.Account
	if _, err := sr.State(&account, protocol.LegacyKeyOption(addrHash)); err != nil {
		if errors.Cause(err) == state.ErrStateNotExist {
			account = state.EmptyAccount()
			return &account, nil
		}
		return nil, err
	}
	return &account, nil
}

// StoreAccount puts updated account state to trie
func StoreAccount(sm protocol.StateManager, addr address.Address, account *state.Account) error {
	addrHash := hash.BytesToHash160(addr.Bytes())
	_, err := sm.PutState(account, protocol.LegacyKeyOption(addrHash))
	return err
}

// Recorded tests if an account has been actually stored
func Recorded(sr protocol.StateReader, addr address.Address) (bool, error) {
	var account state.Account
	_, err := sr.State(&account, protocol.LegacyKeyOption(hash.BytesToHash160(addr.Bytes())))
	if err == nil {
		return true, nil
	}
	if errors.Cause(err) == state.ErrStateNotExist {
		return false, nil
	}
	return false, err
}

// AccountState returns the confirmed account state on the chain
func AccountState(sr protocol.StateReader, addr address.Address) (*state.Account, error) {
	a, _, err := AccountStateWithHeight(sr, addr)
	return a, err
}

// AccountStateWithHeight returns the confirmed account state on the chain with what height the state is read from.
func AccountStateWithHeight(sr protocol.StateReader, addr address.Address) (*state.Account, uint64, error) {
	pkHash := hash.BytesToHash160(addr.Bytes())
	var account state.Account
	h, err := sr.State(&account, protocol.LegacyKeyOption(pkHash))
	if err != nil {
		if errors.Cause(err) == state.ErrStateNotExist {
			account = state.EmptyAccount()
			return &account, h, nil
		}
		return nil, h, errors.Wrapf(err, "error when loading state of %x", pkHash)
	}
	return &account, h, nil
}
