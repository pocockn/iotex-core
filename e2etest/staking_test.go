// Copyright (c) 2020 IoTeX Foundation
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package e2etest

import (
	"bytes"
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/stretchr/testify/require"

	"github.com/iotexproject/go-pkgs/hash"
	"github.com/iotexproject/iotex-address/address"

	"github.com/iotexproject/iotex-core/action"
	"github.com/iotexproject/iotex-core/action/protocol"
	"github.com/iotexproject/iotex-core/action/protocol/poll"
	"github.com/iotexproject/iotex-core/blockchain/genesis"
	"github.com/iotexproject/iotex-core/config"
	"github.com/iotexproject/iotex-core/pkg/unit"
	"github.com/iotexproject/iotex-core/pkg/util/byteutil"
	"github.com/iotexproject/iotex-core/server/itx"
	"github.com/iotexproject/iotex-core/state"
	"github.com/iotexproject/iotex-core/test/identityset"
	"github.com/iotexproject/iotex-core/testutil"
)

func TestStakingContract(t *testing.T) {
	require := require.New(t)

	testReadContract := func(cfg config.Config, t *testing.T) {
		ctx := context.Background()

		// Create a new blockchain
		svr, err := itx.NewServer(cfg)
		require.NoError(err)
		require.NoError(svr.Start(ctx))
		defer func() {
			require.NoError(svr.Stop(ctx))
		}()

		chainID := cfg.Chain.ID
		bc := svr.ChainService(chainID).Blockchain()
		sf := svr.ChainService(chainID).StateFactory()
		ap := svr.ChainService(chainID).ActionPool()
		dao := svr.ChainService(chainID).BlockDAO()
		registry := svr.ChainService(chainID).Registry()
		require.NotNil(bc)
		require.NotNil(registry)
		admin := identityset.PrivateKey(26)
		state0 := hash.BytesToHash160(identityset.Address(26).Bytes())
		var s state.Account
		_, err = sf.State(ctx, &s, protocol.LegacyKeyOption(state0))
		require.NoError(err)
		require.Equal(unit.ConvertIotxToRau(100000000), s.Balance)

		// deploy staking contract
		data, _ := hex.DecodeString("60806040526000805460a060020a60ff021916905534801561002057600080fd5b5060405160408061309d8339810180604052810190808051906020019092919080519060200190929190505050336000806101000a815481600160a060020a030219169083600160a060020a031602179055508160028190555080600381905550610140604051908101604052806000600160a060020a031916815260200160018152602001600081526020014281526020016001151581526020016000815260200133600160a060020a031681526020014281526020016000815260200160008152506004600080815260200190815260200160002060008201518160000160006101000a8154816001606060020a030219169083740100000000000000000000000000000000000000009004021790555060208201518160010155604082015181600201556060820151816003015560808201518160040160006101000a81548160ff02191690831515021790555060a0820151816005015560c08201518160060160006101000a815481600160a060020a030219169083600160a060020a0316021790555060e08201518160070155610100820151816008015561012082015181600901559050506006600033600160a060020a0316600160a060020a031681526020019081526020016000206000908060018154018082558091505090600182039060005260206000200160009091929091909150555060016005819055505050612e69806102346000396000f30060806040526004361061018a5763ffffffff7c0100000000000000000000000000000000000000000000000000000000600035041663030ba25d811461018f57806307c35fc0146101b55780631b0690ed146101f257806324953eaa14610207578063286dd3f5146102705780632f54bf6e146102915780633f4ba83a146102b2578063423ce1ae146102c75780635c975abb146102eb5780635fec5c641461030057806363809953146103155780636c0a5ebd1461032a5780636e7b3017146103e557806376f70003146103fc5780637b24a5fd146104115780637b9417c81461043f5780637d56493714610460578063817b1cd2146104915780638456cb59146104a65780638da5cb5b146104bb57806394a9c0f9146104ec5780639b19251a14610562578063c698d49514610583578063c8fd6ed014610598578063ccfafd5c146105bc578063d09daa9914610638578063d3e41fd2146106a9578063df43a94e146106db578063e2ec6ec3146108ef578063f188768414610944578063f2fde38b14610959575b600080fd5b34801561019b57600080fd5b506101b360048035906024803590810191013561097a565b005b6101e060048035600160a060020a031916906024803591604435151591606435908101910135610d09565b60408051918252519081900360200190f35b3480156101fe57600080fd5b506101e06111e5565b34801561021357600080fd5b506040805160206004803580820135838102808601850190965280855261025c953695939460249493850192918291850190849080828437509497506111eb9650505050505050565b604080519115158252519081900360200190f35b34801561027c57600080fd5b5061025c600160a060020a0360043516611247565b34801561029d57600080fd5b5061025c600160a060020a03600435166112dc565b3480156102be57600080fd5b506101b36112f0565b3480156102d357600080fd5b506101e0600160a060020a0360043516602435611363565b3480156102f757600080fd5b5061025c611393565b34801561030c57600080fd5b506101e06113a3565b34801561032157600080fd5b506101e06113a8565b34801561033657600080fd5b506103456004356024356113af565b604051808481526020018060200180602001838103835285818151815260200191508051906020019060200280838360005b8381101561038f578181015183820152602001610377565b50505050905001838103825284818151815260200191508051906020019060200280838360005b838110156103ce5781810151838201526020016103b6565b505050509050019550505050505060405180910390f35b6101b360048035906024803590810191013561145e565b34801561040857600080fd5b506101e061169f565b34801561041d57600080fd5b506101b3600480359060248035916044351515916064359081019101356116a5565b34801561044b57600080fd5b5061025c600160a060020a0360043516611a4c565b34801561046c57600080fd5b506101b3600480359060248035600160a060020a031691604435918201910135611ae5565b34801561049d57600080fd5b506101e0611c34565b3480156104b257600080fd5b506101b3611c3a565b3480156104c757600080fd5b506104d0611cb2565b60408051600160a060020a039092168252519081900360200190f35b3480156104f857600080fd5b50610507600435602435611cc1565b6040518083815260200180602001828103825283818151815260200191508051906020019060200280838360005b8381101561054d578181015183820152602001610535565b50505050905001935050505060405180910390f35b34801561056e57600080fd5b5061025c600160a060020a0360043516611cda565b34801561058f57600080fd5b506101e0611cef565b3480156105a457600080fd5b506101b3600480359060248035908101910135611cf4565b3480156105c857600080fd5b506105d46004356120e8565b60408051600160a060020a0319909b168b5260208b0199909952898901979097526060890195909552921515608088015260a0870191909152600160a060020a031660c086015260e085015261010084015261012083015251908190036101400190f35b34801561064457600080fd5b50610659600160a060020a036004351661214e565b60408051602080825283518183015283519192839290830191858101910280838360005b8381101561069557818101518382015260200161067d565b505050509050019250505060405180910390f35b3480156106b557600080fd5b506101b3600480359060248035600160a060020a031916916044359182019101356121ba565b3480156106e757600080fd5b506106f660043560243561233f565b604051808981526020018060200180602001806020018060200180602001806020018060200188810388528f818151815260200191508051906020019060200280838360005b8381101561075457818101518382015260200161073c565b5050505090500188810387528e818151815260200191508051906020019060200280838360005b8381101561079357818101518382015260200161077b565b5050505090500188810386528d818151815260200191508051906020019060200280838360005b838110156107d25781810151838201526020016107ba565b5050505090500188810385528c818151815260200191508051906020019060200280838360005b838110156108115781810151838201526020016107f9565b5050505090500188810384528b818151815260200191508051906020019060200280838360005b83811015610850578181015183820152602001610838565b5050505090500188810383528a818151815260200191508051906020019060200280838360005b8381101561088f578181015183820152602001610877565b50505050905001888103825289818151815260200191508051906020019060200280838360005b838110156108ce5781810151838201526020016108b6565b505050509050019f5050505050505050505050505050505060405180910390f35b3480156108fb57600080fd5b506040805160206004803580820135838102808601850190965280855261025c9536959394602494938501929182918501908490808284375094975061262a9650505050505050565b34801561095057600080fd5b506101e0612680565b34801561096557600080fd5b506101b3600160a060020a0360043516612686565b60008054819081908190819060a060020a900460ff161561099a57600080fd5b873315156109e0576040805160e560020a62461bcd02815260206004820152601d6024820152600080516020612dfe833981519152604482015290519081900360640190fd5b600081815260046020526040902060060154600160a060020a03163314610a3f576040805160e560020a62461bcd0281526020600482015260186024820152600080516020612e1e833981519152604482015290519081900360640190fd5b60008981526004602052604081206005015411610acc576040805160e560020a62461bcd02815260206004820152602560248201527f506c6561736520756e7374616b65206669727374206265666f7265207769746860448201527f647261772e000000000000000000000000000000000000000000000000000000606482015290519081900360840190fd5b6000898152600460205260409020600501544290610af3906203f48063ffffffff6126bc16565b1115610b6f576040805160e560020a62461bcd02815260206004820152603f60248201527f5374616b65686f6c646572206e6565647320746f207761697420666f7220332060448201527f64617973206265666f7265207769746864726177696e6720746f6b656e732e00606482015290519081900360840190fd5b6000898152600460205260408082206008808201546009808401548287528587209091018190558086529385209091018190558c845260018201805483546006909401549590915590995091975090955060a060020a029350600160a060020a03169150610bdc896126d2565b600089815260046020819052604080832080546bffffffffffffffffffffffff19168155600181018490556002810184905560038101849055918201805460ff1916905560058201839055600682018054600160a060020a03191690556007820183905560088201839055600990910182905551600160a060020a0384169186156108fc02918791818181858888f19350505050158015610c81573d6000803e3d6000fd5b507ff99c0736fafe9102d41ec0b56c187b26a6e35ae50415dcbecedf73112d0ec7638984868b8b6040518086815260200185600160a060020a031916600160a060020a031916815260200184815260200180602001828103825284848281815260200192508082843760405192018290039850909650505050505050a1505050505050505050565b6000805460a060020a900460ff1615610d2157600080fd5b8460008110158015610d35575061041a8111155b1515610db1576040805160e560020a62461bcd02815260206004820152602860248201527f546865207374616b65206475726174696f6e20697320746f6f20736d616c6c2060448201527f6f72206c61726765000000000000000000000000000000000000000000000000606482015290519081900360840190fd5b6007810615610e30576040805160e560020a62461bcd02815260206004820152602a60248201527f546865207374616b65206475726174696f6e2073686f756c64206265206d756c60448201527f7469706c65206f66203700000000000000000000000000000000000000000000606482015290519081900360840190fd5b600254341015610e8a576040805160e560020a62461bcd02815260206004820152601560248201527f616d6f756e742073686f756c64203e3d203130302e0000000000000000000000604482015290519081900360640190fd5b6003543360009081526006602052604090205410610f18576040805160e560020a62461bcd02815260206004820152602560248201527f4f6e6520616464726573732063616e2068617665207570206c696d697465642060448201527f7079676773000000000000000000000000000000000000000000000000000000606482015290519081900360840190fd5b6101406040519081016040528088600160a060020a031916815260200134815260200187815260200142815260200186151581526020016000815260200133600160a060020a0316815260200142815260200160046000808152602001908152602001600020600801548152602001600081525060046000600554815260200190815260200160002060008201518160000160006101000a8154816bffffffffffffffffffffffff021916908360a060020a9004021790555060208201518160010155604082015181600201556060820151816003015560808201518160040160006101000a81548160ff02191690831515021790555060a0820151816005015560c08201518160060160006101000a815481600160a060020a030219169083600160a060020a0316021790555060e082015181600701556101008201518160080155610120820151816009015590505060055460046000600460008081526020019081526020016000206008015481526020019081526020016000206009018190555060055460046000808152602001908152602001600020600801819055506006600033600160a060020a0316600160a060020a0316815260200190815260200160002060055490806001815401808255809150509060018203906000526020600020016000909192909190915055506005600081548092919060010191905055507fd7812fae7f8126d2df0f5449a2cc0744d2e9d3fc8c161de6193bc4df6c68d365600160055403883489428a338b8b604051808a815260200189600160a060020a031916600160a060020a03191681526020018881526020018781526020018681526020018515151515815260200184600160a060020a0316600160a060020a0316815260200180602001828103825284848281815260200192508082843760405192018290039c50909a5050505050505050505050a150506005546000190195945050505050565b60035481565b6000806111f7336112dc565b151561120257600080fd5b5060005b82518110156112415761122f838281518110151561122057fe5b90602001906020020151611247565b1561123957600191505b600101611206565b50919050565b6000611252336112dc565b151561125d57600080fd5b600160a060020a03821660009081526001602052604090205460ff16156112d757600160a060020a038216600081815260016020908152604091829020805460ff19169055815192835290517ff1abf01a1043b7c244d128e8595cf0c1d10743b022b03a02dffd8ca3bf729f5a9281900390910190a15060015b919050565b600054600160a060020a0391821691161490565b6112f9336112dc565b151561130457600080fd5b60005460a060020a900460ff16151561131c57600080fd5b6000805474ff0000000000000000000000000000000000000000191681556040517f7805862f689e2f13df9f062ff482ad3ad112aca9e0847911ed832e158c525b339190a1565b60066020528160005260406000208181548110151561137e57fe5b90600052602060002001600091509150505481565b60005460a060020a900460ff1681565b600081565b6201518081565b600060608060006113c086866128a0565b9094509250600084111561145657836040519080825280602002602001820160405280156113f8578160200160208202803883390190505b509150600090505b838110156114565760046000848381518110151561141a57fe5b90602001906020020151815260200190815260200160002060070154828281518110151561144457fe5b60209081029091010152600101611400565b509250925092565b60005460a060020a900460ff161561147557600080fd5b600083116114f3576040805160e560020a62461bcd02815260206004820152602860248201527f7079676720302063616e6e6f7420626520756e7374616b656420616e6420776960448201527f7468647261776e2e000000000000000000000000000000000000000000000000606482015290519081900360840190fd5b6000341161154b576040805160e560020a62461bcd02815260206004820152601160248201527f76616c75652063616e6e6f742062652030000000000000000000000000000000604482015290519081900360640190fd5b600083815260046020526040902060060154600160a060020a031615156115bc576040805160e560020a62461bcd02815260206004820152601360248201527f7079676720646f6573206e6f7420657869737400000000000000000000000000604482015290519081900360640190fd5b600083815260046020526040902060010154151561164a576040805160e560020a62461bcd02815260206004820152602160248201527f63616e6e6f742073746f726520746f20612077697468647261776e207079676760448201527f2e00000000000000000000000000000000000000000000000000000000000000606482015290519081900360840190fd5b6000838152600460209081526040918290206001018054340190558151601f840182900482028101820190925282825261169a918591859085908190840183828082843750612b57945050505050565b505050565b61041a81565b60005460a060020a900460ff16156116bc57600080fd5b84331515611702576040805160e560020a62461bcd02815260206004820152601d6024820152600080516020612dfe833981519152604482015290519081900360640190fd5b600081815260046020526040902060060154600160a060020a03163314611761576040805160e560020a62461bcd0281526020600482015260186024820152600080516020612e1e833981519152604482015290519081900360640190fd5b8460008110158015611775575061041a8111155b15156117f1576040805160e560020a62461bcd02815260206004820152602860248201527f546865207374616b65206475726174696f6e20697320746f6f20736d616c6c2060448201527f6f72206c61726765000000000000000000000000000000000000000000000000606482015290519081900360840190fd5b6007810615611870576040805160e560020a62461bcd02815260206004820152602a60248201527f546865207374616b65206475726174696f6e2073686f756c64206265206d756c60448201527f7469706c65206f66203700000000000000000000000000000000000000000000606482015290519081900360840190fd5b6000878152600460205260409020600281015460039091015461189d91620151800263ffffffff6126bc16565b6118b24262015180890263ffffffff6126bc16565b101561192d576040805160e560020a62461bcd028152602060048201526024808201527f63757272656e74207374616b65206475726174696f6e206e6f742066696e697360448201527f6865642e00000000000000000000000000000000000000000000000000000000606482015290519081900360840190fd5b6000878152600460208190526040909120015460ff16156119d7576000878152600460205260409020600201548610156119d7576040805160e560020a62461bcd02815260206004820152602160248201527f63616e6e6f742072656475636520746865207374616b65206475726174696f6e60448201527f2e00000000000000000000000000000000000000000000000000000000000000606482015290519081900360840190fd5b6000878152600460208181526040808420600281018b9055426003820155928301805460ff19168a15151790556005909201929092558051601f8601839004830281018301909152848152611a4391899190879087908190840183828082843750612b57945050505050565b50505050505050565b6000611a57336112dc565b1515611a6257600080fd5b600160a060020a03821660009081526001602052604090205460ff1615156112d757600160a060020a038216600081815260016020818152604092839020805460ff1916909217909155815192835290517fd1bba68c128cc3f427e5831b3c6f99f480b6efa6b9e80c757768f6124158cc3f9281900390910190a1506001919050565b60005460a060020a900460ff1615611afc57600080fd5b83331515611b42576040805160e560020a62461bcd02815260206004820152601d6024820152600080516020612dfe833981519152604482015290519081900360640190fd5b600081815260046020526040902060060154600160a060020a03163314611ba1576040805160e560020a62461bcd0281526020600482015260186024820152600080516020612e1e833981519152604482015290519081900360640190fd5b611baa856126d2565b600085815260046020908152604080832060069081018054600160a060020a031916600160a060020a038a16908117909155845282528083208054600181018255908452928290209092018790558151601f8501829004820281018201909252838252611c2d918791869086908190840183828082843750612b57945050505050565b5050505050565b30315b90565b611c43336112dc565b1515611c4e57600080fd5b60005460a060020a900460ff1615611c6557600080fd5b6000805474ff0000000000000000000000000000000000000000191660a060020a1781556040517f6985a02210a168e66602d3235cb6db0e70f92b3ba4d376a33c0f3d9434bff6259190a1565b600054600160a060020a031681565b60006060611ccf84846128a0565b915091509250929050565b60016020526000908152604090205460ff1681565b600381565b60005460a060020a900460ff1615611d0b57600080fd5b82331515611d51576040805160e560020a62461bcd02815260206004820152601d6024820152600080516020612dfe833981519152604482015290519081900360640190fd5b600081815260046020526040902060060154600160a060020a03163314611db0576040805160e560020a62461bcd0281526020600482015260186024820152600080516020612e1e833981519152604482015290519081900360640190fd5b60008411611e2e576040805160e560020a62461bcd02815260206004820152602860248201527f7079676720302063616e6e6f7420626520756e7374616b656420616e6420776960448201527f7468647261776e2e000000000000000000000000000000000000000000000000606482015290519081900360840190fd5b6000848152600460208190526040909120015460ff1615611ee5576040805160e560020a62461bcd02815260206004820152604860248201527f43616e6e6f7420756e7374616b652077697468206e6f6e446563617920666c6160448201527f672e204e65656420746f2064697361626c65206e6f6e2d6465636179206d6f6460648201527f652066697273742e000000000000000000000000000000000000000000000000608482015290519081900360a40190fd5b600084815260046020526040902060028101546003909101544291611f159190620151800263ffffffff6126bc16565b1115611fb8576040805160e560020a62461bcd028152602060048201526044602482018190527f5374616b696e672074696d6520646f6573206e6f742065787069726520796574908201527f2e20506c65617365207761697420756e74696c207374616b696e67206578706960648201527f7265732e00000000000000000000000000000000000000000000000000000000608482015290519081900360a40190fd5b60008481526004602052604090206005015415612045576040805160e560020a62461bcd02815260206004820152602b60248201527f556e7374616b656420616c72656164792e204e6f206e65656420746f20756e7360448201527f74616b6520616761696e2e000000000000000000000000000000000000000000606482015290519081900360840190fd5b60008481526004602090815260409182902042600582015580546001909101548351888152600160a060020a031960a060020a909302928316938101939093529282018390526080606083018181529083018690527f9954bdedc474e937b39bbb080fc136e2edf1cef61f0906d36203267f4930762e93889390918891889160a0820184848082843760405192018290039850909650505050505050a150505050565b6004602081905260009182526040909120805460018201546002830154600384015494840154600585015460068601546007870154600888015460099098015460a060020a909702989597949660ff909416949293600160a060020a039092169290918a565b600160a060020a0381166000908152600660209081526040918290208054835181840281018401909452808452606093928301828280156121ae57602002820191906000526020600020905b81548152602001906001019080831161219a575b50505050509050919050565b60005460a060020a900460ff16156121d157600080fd5b83331515612217576040805160e560020a62461bcd02815260206004820152601d6024820152600080516020612dfe833981519152604482015290519081900360640190fd5b600081815260046020526040902060060154600160a060020a03163314612276576040805160e560020a62461bcd0281526020600482015260186024820152600080516020612e1e833981519152604482015290519081900360640190fd5b600085815260046020526040902060050154156122dd576040805160e560020a62461bcd02815260206004820152601f60248201527f63616e6e6f74207265766f746520647572696e6720756e7374616b696e672e00604482015290519081900360640190fd5b60008581526004602090815260409182902080546bffffffffffffffffffffffff191660a060020a88041790558151601f8501829004820281018201909252838252611c2d918791869086908190840183828082843750612b57945050505050565b600060608060608060608060606000612356612d57565b6123608c8c6128a0565b909a50985060008a111561261b5789604051908082528060200260200182016040528015612398578160200160208202803883390190505b509750896040519080825280602002602001820160405280156123c5578160200160208202803883390190505b509650896040519080825280602002602001820160405280156123f2578160200160208202803883390190505b5095508960405190808252806020026020018201604052801561241f578160200160208202803883390190505b5094508960405190808252806020026020018201604052801561244c578160200160208202803883390190505b50935089604051908082528060200260200182016040528015612479578160200160208202803883390190505b509250600091505b8982101561261b57600460008a8481518110151561249b57fe5b6020908102919091018101518252818101929092526040908101600020815161014081018352815460a060020a02600160a060020a0319168152600182015493810193909352600281015491830191909152600381015460608301819052600482015460ff1615156080840152600582015460a08401526006820154600160a060020a031660c0840152600782015460e0840152600882015461010084015260099091015461012083015289519192509089908490811061255857fe5b602090810290910101526040810151875188908490811061257557fe5b602090810290910101526080810151865190159087908490811061259557fe5b911515602092830290910182015281015185518690849081106125b457fe5b60209081029091010152805184518590849081106125ce57fe5b600160a060020a031990921660209283029091019091015260c081015183518490849081106125f957fe5b600160a060020a03909216602092830290910190910152600190910190612481565b50509295985092959890939650565b600080612636336112dc565b151561264157600080fd5b5060005b82518110156112415761266e838281518110151561265f57fe5b90602001906020020151611a4c565b1561267857600191505b600101612645565b60025481565b61268f336112dc565b151561269a57600080fd5b60008054600160a060020a031916600160a060020a0392909216919091179055565b6000828201838110156126cb57fe5b9392505050565b6000818152600460209081526040808320600690810154600160a060020a031680855292528220549091908110612779576040805160e560020a62461bcd02815260206004820152602c60248201527f45787065637420746865206f776e657220686173206174206c65617374206f6e60448201527f65207079676720696e6465780000000000000000000000000000000000000000606482015290519081900360840190fd5b5060005b600160a060020a0382166000908152600660205260409020548110156127e257600160a060020a03821660009081526006602052604090208054849190839081106127c457fe5b906000526020600020015414156127da576127e2565b60010161277d565b600160a060020a0382166000908152600660205260409020546000190181101561287157600160a060020a038216600090815260066020526040902080546001830190811061282d57fe5b6000918252602080832090910154600160a060020a03851683526006909152604090912080548390811061285d57fe5b6000918252602090912001556001016127e2565b600160a060020a038216600090815260066020526040902080549061289a906000198301612dc0565b50505050565b600060606128ac612d57565b600080851180156128be575061138885105b15156128c957600080fd5b600086815260046020818152604092839020835161014081018552815460a060020a02600160a060020a0319168152600182015481840152600282015481860152600382015460608201529281015460ff1615156080840152600581015460a08401526006810154600160a060020a031660c0840152600781015460e0840152600881015461010084015260090154610120830152825188815288820281019091019092529250858015612987578160200160208202803883390190505b509250600090505b84811015612b4d575b60008261012001511180156129c25750610120820151600090815260046020526040812060050154115b15612a715761012091820151600090815260046020818152604092839020835161014081018552815460a060020a02600160a060020a0319168152600182015492810192909252600281015493820193909352600383015460608201529082015460ff1615156080820152600582015460a08201526006820154600160a060020a031660c0820152600782015460e0820152600882015461010082015260099091015492810192909252612998565b6101208201511515612a8257612b4d565b8161012001518382815181101515612a9657fe5b6020908102919091018101919091526101209283015160009081526004808352604091829020825161014081018452815460a060020a02600160a060020a031916815260018083015495820195909552600282015493810193909352600381015460608401529081015460ff1615156080830152600581015460a08301526006810154600160a060020a031660c0830152600781015460e0830152600881015461010083015260090154938101939093520161298f565b9250509250929050565b612b5f612d57565b6004600084815260200190815260200160002061014060405190810160405290816000820160009054906101000a900460a060020a02600160a060020a031916600160a060020a03191681526020016001820154815260200160028201548152602001600382015481526020016004820160009054906101000a900460ff16151515158152602001600582015481526020016006820160009054906101000a9004600160a060020a0316600160a060020a0316600160a060020a03168152602001600782015481526020016008820154815260200160098201548152505090507f0b074423c8a0f26c131cd7c88b19ef6adf084b812c97bdd1fb9dcf339ee9a38783826000015183602001518460400151856060015186608001518760c00151896040518089815260200188600160a060020a031916600160a060020a03191681526020018781526020018681526020018581526020018415151515815260200183600160a060020a0316600160a060020a0316815260200180602001828103825283818151815260200191508051906020019080838360005b83811015612d11578181015183820152602001612cf9565b50505050905090810190601f168015612d3e5780820380516001836020036101000a031916815260200191505b50995050505050505050505060405180910390a1505050565b610140604051908101604052806000600160a060020a0319168152602001600081526020016000815260200160008152602001600015158152602001600081526020016000600160a060020a031681526020016000815260200160008152602001600081525090565b81548183558181111561169a5760008381526020902061169a918101908301611c3791905b80821115612df95760008155600101612de5565b5090560073656e6465722073686f756c646e27742062652061646472657373203000000073656e646572206973206e6f7420746865206f776e65722e0000000000000000a165627a7a723058209fa15a477d62e4abdbbaf44343516ca6d6aad780e231ea577e62219d257b0db400290000000000000000000000000000000000000000000000056bc75e2d631000000000000000000000000000000000000000000000000000000000000000000064")
		fixedTime := time.Unix(cfg.Genesis.Timestamp, 0)
		ex, err := action.SignedExecution(action.EmptyAddress, admin, 1, big.NewInt(0), 10000000, big.NewInt(testutil.TestGasPriceInt64), data)
		require.NoError(err)

		deployHash, err := ex.Hash()
		require.NoError(err)
		require.NoError(ap.Add(context.Background(), ex))
		blk, err := bc.MintNewBlock(fixedTime)
		require.NoError(err)
		require.NoError(bc.CommitBlock(blk))
		r, err := dao.GetReceiptByActionHash(deployHash, 1)
		require.NoError(err)
		require.Equal(r.ContractAddress, "io1nw4l6qpph9apnzrmfk3u2dk28y5e05dpnk6nv0")

		// 20 voters, each create 60 buckets
		staking, err := newStakingABI()
		require.NoError(err)
		numVoter := 20
		numBucket := uint64(60)
		fixedAmount := unit.ConvertIotxToRau(200)
		for i := 0; i < numVoter; i++ {
			sk := identityset.PrivateKey(i)
			addr := identityset.Address(i).String()
			for nonce := uint64(0); nonce < numBucket; nonce++ {
				data, err := staking.createStake(addr, nonce)
				require.NoError(err)
				require.True(len(data) > 0)
				ex, err := action.SignedExecution(r.ContractAddress, sk, nonce+1, fixedAmount, 1000000, big.NewInt(testutil.TestGasPriceInt64), data)
				require.NoError(err)
				require.NoError(ap.Add(context.Background(), ex))
			}
			blk, err = bc.MintNewBlock(fixedTime)
			require.NoError(err)
			require.NoError(bc.CommitBlock(blk))

			state0 = hash.BytesToHash160(identityset.Address(i).Bytes())
			_, err = sf.State(ctx, &s, protocol.LegacyKeyOption(state0))
			require.NoError(err)
			require.Equal(unit.ConvertIotxToRau(100000000-int64(numBucket)*200), s.Balance)
		}

		// read from contract
		ns, err := poll.NewNativeStaking(func(ctx context.Context, contract string, params []byte, correctGas bool) ([]byte, error) {
			gasLimit := uint64(1000000)
			if correctGas {
				gasLimit *= 10
			}
			ex, err := action.NewExecution(contract, 1, big.NewInt(0), gasLimit, big.NewInt(0), params)
			if err != nil {
				return nil, err
			}

			addr, err := address.FromString(address.ZeroAddress)
			if err != nil {
				return nil, err
			}

			data, _, err := sf.SimulateExecution(ctx, addr, ex, dao.GetBlockHash)

			return data, err
		})
		require.NoError(err)
		ns.SetContract(r.ContractAddress)

		height, err := dao.Height()
		require.NoError(err)
		blk, err = dao.GetBlockByHeight(height)
		require.NoError(err)
		ctx = genesis.WithGenesisContext(
			protocol.WithBlockchainCtx(
				protocol.WithRegistry(ctx, registry),
				protocol.BlockchainCtx{
					Tip: protocol.TipInfo{
						Height:    height,
						Hash:      blk.HashHeader(),
						Timestamp: blk.Timestamp(),
					},
				}),
			cfg.Genesis,
		)
		bcCtx := protocol.MustGetBlockchainCtx(ctx)
		_, err = ns.Votes(ctx, bcCtx.Tip.Timestamp, false)
		require.Equal(poll.ErrNoData, err)
		tally, err := ns.Votes(ctx, bcCtx.Tip.Timestamp, true)
		require.NoError(err)
		require.Equal(numVoter*int(numBucket), len(tally.Candidates))
		require.Equal(numVoter*int(numBucket), len(tally.Buckets))

		// verify all read buckets
		for i := 0; i < numVoter; i++ {
			addr := identityset.Address(i).String()
			addrBytes := identityset.Address(i).Bytes()
			for nonce := uint64(0); nonce < numBucket; nonce++ {
				v := tally.Buckets[i*int(numBucket)+int(nonce)]
				name := fakeCanName(addr, nonce)
				require.Equal(0, bytes.Compare(name[:], v.Candidate()))
				require.Equal(0, bytes.Compare(addrBytes, v.Voter()))
				require.Equal(fixedAmount, v.Amount())
				require.Equal(time.Duration(nonce*7*24)*time.Hour, v.Duration())
				require.False(v.Decay())

				c, ok := tally.Candidates[name]
				require.True(ok)
				require.Equal(0, bytes.Compare(name[:], c.CanName))
				require.True(c.Votes.Cmp(fixedAmount) >= 0)
			}
		}
	}

	cfg := config.Default
	testTriePath, err := testutil.PathOfTempFile("trie")
	require.NoError(err)
	testDBPath, err := testutil.PathOfTempFile("db")
	require.NoError(err)
	testIndexPath, err := testutil.PathOfTempFile("index")
	require.NoError(err)
	testBloomfilterIndexPath, err := testutil.PathOfTempFile("bloomfilterindex")
	require.NoError(err)
	testCandidateIndexPath, err := testutil.PathOfTempFile("candidateindex")
	require.NoError(err)
	testSystemLogPath, err := testutil.PathOfTempFile("systemlog")
	require.NoError(err)
	testConsensusPath, err := testutil.PathOfTempFile("consensus")
	require.NoError(err)
	defer func() {
		testutil.CleanupPath(testTriePath)
		testutil.CleanupPath(testDBPath)
		testutil.CleanupPath(testIndexPath)
		testutil.CleanupPath(testBloomfilterIndexPath)
		testutil.CleanupPath(testCandidateIndexPath)
		testutil.CleanupPath(testSystemLogPath)
		testutil.CleanupPath(testConsensusPath)
		// clear the gateway
		delete(cfg.Plugins, config.GatewayPlugin)
	}()

	cfg.ActPool.MinGasPriceStr = "0"
	cfg.Chain.TrieDBPatchFile = ""
	cfg.Chain.TrieDBPath = testTriePath
	cfg.Chain.ChainDBPath = testDBPath
	cfg.Chain.IndexDBPath = testIndexPath
	cfg.Chain.BloomfilterIndexDBPath = testBloomfilterIndexPath
	cfg.Chain.CandidateIndexDBPath = testCandidateIndexPath
	cfg.System.SystemLogDBPath = testSystemLogPath
	cfg.Consensus.RollDPoS.ConsensusDBPath = testConsensusPath
	cfg.Chain.ProducerPrivKey = "a000000000000000000000000000000000000000000000000000000000000000"
	cfg.Consensus.Scheme = config.RollDPoSScheme
	cfg.Genesis.NumDelegates = 1
	cfg.Genesis.NumSubEpochs = 10
	cfg.Genesis.Delegates = []genesis.Delegate{
		{
			OperatorAddrStr: identityset.Address(0).String(),
			RewardAddrStr:   identityset.Address(0).String(),
			VotesStr:        "10",
		},
	}
	cfg.Genesis.PollMode = "lifeLong"
	cfg.Genesis.EnableGravityChainVoting = false
	cfg.Plugins[config.GatewayPlugin] = true
	cfg.Chain.EnableAsyncIndexWrite = false
	cfg.Genesis.AleutianBlockHeight = 2

	t.Run("test read staking contract", func(t *testing.T) {
		testReadContract(cfg, t)
	})
}

type stakingABI struct {
	abi abi.ABI
}

func newStakingABI() (*stakingABI, error) {
	abi, err := abi.JSON(strings.NewReader(poll.NsAbi))
	if err != nil {
		return nil, err
	}
	return &stakingABI{
		abi: abi,
	}, nil
}

func fakeCanName(addr string, index uint64) [12]byte {
	var name [12]byte
	copy(name[:4], addr[3:])
	copy(name[4:], byteutil.Uint64ToBytesBigEndian(index))
	return name
}

func (s *stakingABI) createStake(addr string, index uint64) ([]byte, error) {
	name := fakeCanName(addr, index)
	data := hash.Hash256b(name[:])
	return s.abi.Pack("createPygg", name, big.NewInt(7*int64(index)), true, data[:])
}
