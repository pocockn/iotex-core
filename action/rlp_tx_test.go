package action

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/golang/protobuf/proto"
	"github.com/iotexproject/go-pkgs/crypto"
	"github.com/iotexproject/go-pkgs/hash"
	"github.com/iotexproject/iotex-address/address"
	"github.com/iotexproject/iotex-proto/golang/iotextypes"
	"github.com/stretchr/testify/require"

	"github.com/iotexproject/iotex-core/config"
)

func TestGenerateRlp(t *testing.T) {
	require := require.New(t)

	ab := AbstractAction{
		version:  1,
		nonce:    2,
		gasLimit: 1000,
		gasPrice: new(big.Int),
	}
	rlpTsf := &Transfer{
		AbstractAction: ab,
		recipient:      "io1x9qa70ewgs24xwak66lz5dgm9ku7ap80vw3071",
	}
	rlpTsf1 := &Transfer{
		AbstractAction: ab,
		amount:         big.NewInt(100),
		recipient:      "",
	}
	hT1, _ := hex.DecodeString("87e39e819193ae46472eb1320739b34c4c3b38ea321c7cc503432bdcfd0cbf15")
	rlpTsf2 := &Transfer{
		AbstractAction: ab,
		recipient:      "io1x9qa70ewgs24xwak66lz5dgm9ku7ap80vw3070",
	}
	hT2, _ := hex.DecodeString("eaaf38a552809a9bdb1509c8093bd2c74eb07baff862dae692c1d2b865478b14")
	rlpExec := &Execution{
		AbstractAction: ab,
		amount:         big.NewInt(100),
		data:           signByte,
	}
	hE1, _ := hex.DecodeString("fcdd0c3d07f438d6e67ea852b40e5dc256d75f5e1fa9ac3ca96030efeb634150")
	rlpExec1 := &Execution{
		AbstractAction: ab,
		contract:       "io1x9qa70ewgs24xwak66lz5dgm9ku7ap80vw3070",
		amount:         big.NewInt(100),
		data:           signByte,
	}
	hE2, _ := hex.DecodeString("fee3db88ee7d7defa9eded672d08fc8641f760f3a11d404a53276ad6f412b8a5")
	rlpTests := []struct {
		act  rlpTransaction
		sig  []byte
		err  string
		hash hash.Hash256
	}{
		{nil, validSig, "nil action to generate RLP tx", hash.ZeroHash256},
		{rlpTsf, validSig, "invalid recipient address", hash.ZeroHash256},
		{rlpTsf1, signByte, "invalid signature length =", hash.ZeroHash256},
		{rlpTsf1, validSig, "", hash.BytesToHash256(hT1)},
		{rlpTsf2, validSig, "", hash.BytesToHash256(hT2)},
		{rlpExec, validSig, "", hash.BytesToHash256(hE1)},
		{rlpExec1, validSig, "", hash.BytesToHash256(hE2)},
	}

	for _, v := range rlpTests {
		_, err := generateRlpTx(v.act)
		if err != nil {
			require.Contains(err.Error(), v.err)
		}
		h, err := rlpSignedHash(v.act, 4689, v.sig)
		if err != nil {
			require.Contains(err.Error(), v.err)
		}
		require.Equal(v.hash, h)
	}
}

func TestRlpDecodeVerify(t *testing.T) {
	// register the extern chain ID
	config.SetEVMNetworkID(config.Default.Chain.EVMNetworkID)

	require := require.New(t)

	rlpTests := []struct {
		raw    string
		nonce  uint64
		limit  uint64
		price  string
		amount string
		to     string
		isTsf  bool
		data   bool
		hash   string
		pubkey string
		pkhash string
	}{
		{
			"f86e8085e8d4a51000825208943141df3f2e4415533bb6d6be2a351b2db9ee84ef88016345785d8a0000808224c6a0204d25fc0d7d8b3fdf162c6ee820f888f5533b1c382d79d5cbc8ec1d9091a9a8a016f1a58d7e0d0fd24be800f64a2d6433c5fcb31e3fc7562b7fbe62bc382a95bb",
			0,
			21000,
			"1000000000000",
			"100000000000000000",
			"io1x9qa70ewgs24xwak66lz5dgm9ku7ap80vw3070",
			true,
			false,
			"eead45fe6b510db9ed6dce9187280791c04bbaadd90c54a7f4b1f75ced382ff1",
			"041ba784140be115e8fa8698933e9318558a895c75c7943100f0677e4d84ff2763ff68720a0d22c12d093a2d692d1e8292c3b7672fccf3b3db46a6e0bdad93be17",
			"87eea07540789af85b64947aea21a3f00400b597",
		},
		{
			"f8ab0d85e8d4a5100082520894ac7ac39de679b19aae042c0ce19facb86e0a411780b844a9059cbb0000000000000000000000003141df3f2e4415533bb6d6be2a351b2db9ee84ef000000000000000000000000000000000000000000000000000000003b9aca008224c5a0fac4e25db03c99fec618b74a962d322a334234696eb62c7e5b9889132ff4f4d7a02c88e451572ca36b6f690ce23ff9d6695dd71e888521fa706a8fc8c279099a61",
			13,
			21000,
			"1000000000000",
			"0",
			"io143av880x0xce4tsy9sxwr8avhphq5sghum77ct",
			false,
			true,
			"7467dd6ccd4f3d7b6dc0002b26a45ad0b75a1793da4e3557cf6ff2582cbe25c9",
			"041ba784140be115e8fa8698933e9318558a895c75c7943100f0677e4d84ff2763ff68720a0d22c12d093a2d692d1e8292c3b7672fccf3b3db46a6e0bdad93be17",
			"87eea07540789af85b64947aea21a3f00400b597",
		},
		{
			"f9024f2e830f42408381b3208080b901fc608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555061019c806100606000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c8063445df0ac146100465780638da5cb5b14610064578063fdacd576146100ae575b600080fd5b61004e6100dc565b6040518082815260200191505060405180910390f35b61006c6100e2565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b6100da600480360360208110156100c457600080fd5b8101908080359060200190929190505050610107565b005b60015481565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141561016457806001819055505b5056fea265627a7a72315820e54fe55a78b9d8bec22b4d3e6b94b7e59799daee3940423eb1aa30fe643eeb9a64736f6c634300051000328224c5a0439310c2d5509fc42486171b910cf8107542c86e23202a3a8ba43129cabcdbfea038966d36b41916f619c64bdc8c3ddcb021b35ea95d44875eb8201e9422fd98f0",
			46,
			8500000,
			"1000000",
			"0",
			EmptyAddress,
			false,
			true,
			"b676128dae841742e3ab6e518acb30badc6b26230fe870821d1de08c85823067",
			"049c6567f527f8fc98c0875d3d80097fcb4d5b7bfe037fc9dd5dbeaf563d58d7ff17a4f2b85df9734ecdb276622738e28f0b7cf224909ab7b128c5ca748729b0d2",
			"1904bfcb93edc9bf961eead2e5c0de81dcc1d37d",
		},
	}

	for _, v := range rlpTests {
		encoded, err := hex.DecodeString(v.raw)
		require.NoError(err)

		// decode received RLP tx
		tx := types.Transaction{}
		require.NoError(rlp.DecodeBytes(encoded, &tx))

		// extract signature and recover pubkey
		w, r, s := tx.RawSignatureValues()
		recID := uint32(w.Int64()) - 2*config.EVMNetworkID() - 8
		sig := make([]byte, 64, 65)
		rSize := len(r.Bytes())
		copy(sig[32-rSize:32], r.Bytes())
		sSize := len(s.Bytes())
		copy(sig[64-sSize:], s.Bytes())
		sig = append(sig, byte(recID))

		// recover public key
		rawHash := types.NewEIP155Signer(big.NewInt(int64(config.EVMNetworkID()))).Hash(&tx)
		pubkey, err := crypto.RecoverPubkey(rawHash[:], sig)
		require.NoError(err)
		require.Equal(v.pubkey, pubkey.HexString())
		require.Equal(v.pkhash, hex.EncodeToString(pubkey.Hash()))

		// convert to our Execution
		pb := &iotextypes.Action{
			Encoding: iotextypes.Encoding_ETHEREUM_RLP,
		}
		pb.Core = convertToNativeProto(&tx, v.isTsf)
		pb.SenderPubKey = pubkey.Bytes()
		pb.Signature = sig

		// send on wire
		bs, err := proto.Marshal(pb)
		require.NoError(err)

		// receive from API
		proto.Unmarshal(bs, pb)
		selp := SealedEnvelope{}
		require.NoError(selp.LoadProto(pb))
		rlpTx, err := actionToRLP(selp.Action())
		require.NoError(err)

		// verify against original tx
		require.Equal(v.nonce, rlpTx.Nonce())
		require.Equal(v.price, rlpTx.GasPrice().String())
		require.Equal(v.limit, rlpTx.GasLimit())
		require.Equal(v.to, rlpTx.Recipient())
		require.Equal(v.amount, rlpTx.Amount().String())
		require.Equal(v.data, len(rlpTx.Payload()) > 0)
		h := selp.Hash()
		require.Equal(v.hash, hex.EncodeToString(h[:]))
		require.Equal(pubkey, selp.SrcPubkey())
		require.True(bytes.Equal(sig, selp.signature))
		raw, err := selp.envelopeHash()
		require.NoError(err)
		require.True(bytes.Equal(rawHash[:], raw[:]))
		require.NotEqual(raw, h)
		require.NoError(Verify(selp))
	}
}

func convertToNativeProto(tx *types.Transaction, isTsf bool) *iotextypes.ActionCore {
	pb := iotextypes.ActionCore{
		Version:  1,
		Nonce:    tx.Nonce(),
		GasLimit: tx.Gas(),
		GasPrice: tx.GasPrice().String(),
	}

	if isTsf {
		tsf := &Transfer{}
		tsf.nonce = tx.Nonce()
		tsf.gasLimit = tx.Gas()
		tsf.gasPrice = tx.GasPrice()
		tsf.amount = tx.Value()
		ioAddr, _ := address.FromBytes(tx.To().Bytes())
		tsf.recipient = ioAddr.String()
		tsf.payload = tx.Data()

		pb.Action = &iotextypes.ActionCore_Transfer{
			Transfer: tsf.Proto(),
		}
	} else {
		ex := &Execution{}
		ex.nonce = tx.Nonce()
		ex.gasLimit = tx.Gas()
		ex.gasPrice = tx.GasPrice()
		ex.amount = tx.Value()
		if tx.To() != nil {
			ioAddr, _ := address.FromBytes(tx.To().Bytes())
			ex.contract = ioAddr.String()
		}
		ex.data = tx.Data()

		pb.Action = &iotextypes.ActionCore_Execution{
			Execution: ex.Proto(),
		}
	}
	return &pb
}

func TestCorruptedTestnetRlpTx(t *testing.T) {
	require := require.New(t)
	// register the extern chain ID
	config.SetEVMNetworkID(4690)

	var (
		act  = iotextypes.Action{}
		selp SealedEnvelope
	)
	for _, v := range []struct {
		txHash, txBytes, rawHash, txSig     string
		sender, amount, recipient, gasPrice string
		nonce, gasLimit                     uint64
	}{
		{
			"861ce319a8d467764f5b63096c58c6dbe30b47d1bcc393c13692a08bfd56ceed",
			"0a4910011888a401220d3130303030303030303030303052320a0531652b32311229696f31396d6668766c3875686e3435396c366c7865706466686d30733564656775726e39703977733712410437ad28681a606ff0b212b932b7eea10331aa66e1c9ec193453d2f8330626f4f18a3fcfe4744e0070beb97ccc7cc8cd0c4f6f8722d5e550781daebaf9e92e3fda1a41c82981e9fd6f512903bcb75e9c46956a69c67e4645ea3701de0e2283aaaa442933f44a1c6e603e07b075bc819323311fbb99161bec3734db859b46e5e0d8d3511b2001",
			"db1de85a4d152249c4038576c503216809c59f32420713333b9f5be394341945",
			"c82981e9fd6f512903bcb75e9c46956a69c67e4645ea3701de0e2283aaaa442933f44a1c6e603e07b075bc819323311fbb99161bec3734db859b46e5e0d8d3511b",
			"io1y3lhu7mmzgl3ullyjrz5f69rkkew4wqu58m9n0",
			"1e+21",
			"io19mfhvl8uhn459l6lxepdfhm0s5degurn9p9ws7",
			"1000000000000",
			1, 21000,
		},
		{
			"dd6c6d4ffd0c2d99b985d9c995bb1b7b8771edcdd9d7c5f96280f22074cdc942",
			"0a4910031888a401220d3130303030303030303030303052320a0531652b32311229696f31396d6668766c3875686e3435396c366c7865706466686d30733564656775726e39703977733712410437ad28681a606ff0b212b932b7eea10331aa66e1c9ec193453d2f8330626f4f18a3fcfe4744e0070beb97ccc7cc8cd0c4f6f8722d5e550781daebaf9e92e3fda1a41b69c99bc7d7e7f62747f915206070afec40e78667218bb2d47696780fe90330e7dca8ff21b56889bdffd55f23052328656fb884797f1bcb1fe6738d310d7d46f1b2001",
			"26ccd9b5f09caf45cf860ea96f9f8c513e6781aa3d6ef3348a51a959f26456f5",
			"b69c99bc7d7e7f62747f915206070afec40e78667218bb2d47696780fe90330e7dca8ff21b56889bdffd55f23052328656fb884797f1bcb1fe6738d310d7d46f1b",
			"io1y3lhu7mmzgl3ullyjrz5f69rkkew4wqu58m9n0",
			"1e+21",
			"io19mfhvl8uhn459l6lxepdfhm0s5degurn9p9ws7",
			"1000000000000",
			3, 21000,
		},
		{
			"3a29742229044b83595bf815c72e66790faf40021e6c3304e94829dc8011a463",
			"0a4910051888a401220d3130303030303030303030303052320a0531652b32311229696f31396d6668766c3875686e3435396c366c7865706466686d30733564656775726e39703977733712410437ad28681a606ff0b212b932b7eea10331aa66e1c9ec193453d2f8330626f4f18a3fcfe4744e0070beb97ccc7cc8cd0c4f6f8722d5e550781daebaf9e92e3fda1a417d170ae4c369e8cbbdcb1b6e78acc8f39e9c7160778a471d00e2ef583abb47a50264fbde98185c528774b1e8ec95cdc84825a9169dfe70d78a39f0859de448bf1b2001",
			"def5f601d0ae1d44ee8ecbbd5a8421815ea6e207ed978f6dd8b300abf3c62bb9",
			"7d170ae4c369e8cbbdcb1b6e78acc8f39e9c7160778a471d00e2ef583abb47a50264fbde98185c528774b1e8ec95cdc84825a9169dfe70d78a39f0859de448bf1b",
			"io1y3lhu7mmzgl3ullyjrz5f69rkkew4wqu58m9n0",
			"1e+21",
			"io19mfhvl8uhn459l6lxepdfhm0s5degurn9p9ws7",
			"1000000000000",
			5, 21000,
		},
	} {
		// verify protobuf data
		txBytes, _ := hex.DecodeString(v.txBytes)
		require.NoError(proto.Unmarshal(txBytes, &act))
		core := act.Core
		require.Zero(core.Version)
		require.Equal(v.nonce, core.Nonce)
		require.Equal(v.gasLimit, core.GasLimit)
		require.Equal(v.gasPrice, core.GasPrice)
		require.Zero(core.ChainID)
		tsf := core.GetTransfer()
		require.NotNil(tsf)
		require.Equal(v.amount, tsf.Amount)
		require.Equal(v.recipient, tsf.Recipient)
		pk, err := crypto.BytesToPublicKey(act.SenderPubKey)
		require.NoError(err)
		addr, err := address.FromBytes(pk.Hash())
		require.Equal(v.sender, addr.String())
		recvSig, _ := hex.DecodeString(v.txSig)
		require.Equal(recvSig, act.Signature)
		require.Equal(iotextypes.Encoding_ETHEREUM_RLP, act.Encoding)

		// verify selp data
		require.NoError(selp.LoadProto(&act))
		require.Equal(recvSig, selp.signature)
		elpHash, err := selp.envelopeHash()
		require.NoError(err)
		recvRawHash, _ := hex.DecodeString(v.rawHash)
		require.Equal(recvRawHash, elpHash[:])
		selpHash := selp.Hash()
		recvTxHash, _ := hex.DecodeString(v.txHash)
		require.Equal(recvTxHash, selpHash[:])
		require.Error(Verify(selp))

		// verify embedded tx
		tx, ok := selp.Envelope.Action().(rlpTransaction)
		require.True(ok)
		require.Equal(v.nonce, tx.Nonce())
		require.Equal(v.gasPrice, tx.GasPrice().String())
		require.Equal(v.gasLimit, tx.GasLimit())
		require.Equal(v.recipient, tx.Recipient())
		require.NotEqual(v.amount, tx.Amount().String())
	}
}
