package config

import (
	"context"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	associatedtokenaccount "github.com/gagliardetto/solana-go/programs/associated-token-account"
	compute_budget "github.com/gagliardetto/solana-go/programs/compute-budget"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
	hc "github.com/hellodex/HelloSecurity/api/common"
	"github.com/hellodex/HelloSecurity/log"
	"github.com/hellodex/HelloSecurity/model"
	"github.com/hellodex/HelloSecurity/wallet"
	"github.com/hellodex/HelloSecurity/wallet/enc"
	"github.com/mr-tron/base58"
)

const maxRetries = 30

var transferFnSignature = []byte("transfer(address,uint256)")

const erc20ABI = `[{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]`

func (t ChainConfig) HandleMessage(messageStr string, to string, typecode string, value *big.Int, wg *model.WalletGenerated) (txhash string, sig []byte, err error) {
	if len(t.GetRpc()) == 0 {
		return txhash, sig, errors.New("rpc_config")
	}

	if wg.ChainCode == "SOLANA" {
		message, _ := base64.StdEncoding.DecodeString(messageStr)
		if typecode == "sign" {
			sig, err = enc.Porter().SigSol(wg, message)
			if err != nil {
				log.Error("type=", typecode, err)
				return txhash, sig, err
			}
			return txhash, sig, err
		}
		c := rpc.New(t.GetRpc()[0])

		tx, _ := solana.TransactionFromDecoder(bin.NewBinDecoder(message))
		hashResult, err := c.GetLatestBlockhash(context.Background(), rpc.CommitmentFinalized)
		if err != nil {
			return txhash, sig, err
		}
		tx.Message.RecentBlockhash = hashResult.Value.Blockhash

		sig, err = enc.Porter().SigSol(wg, message)
		if err != nil {
			return txhash, sig, err
		}
		tx.Signatures = []solana.Signature{solana.Signature(sig)}
		txhash, err := c.SendTransaction(context.Background(), tx)

		return base58.Encode(txhash[:]), sig, err
	} else { // for all evm
		message, err := hexutil.Decode(messageStr)
		if err != nil {
			return txhash, sig, err
		}
		if typecode == "sign" {
			sig, err = enc.Porter().SigEth(wg, message)
			if err != nil {
				return txhash, sig, err
			}
			return txhash, sig, err
		}
		client, _ := ethclient.Dial(t.GetRpc()[0])

		nonce, err := client.PendingNonceAt(context.Background(), common.HexToAddress(wg.Wallet))
		if err != nil {
			return txhash, sig, err
		}

		gasPrice, err := client.SuggestGasPrice(context.Background())
		if err != nil {
			return txhash, sig, err
		}

		value := value
		gasLimit := uint64(500000)
		tx := types.NewTransaction(nonce, common.HexToAddress(to), value, gasLimit, gasPrice, message)

		// 查询链 ID
		chainID, err := client.NetworkID(context.Background())
		if err != nil {
			return txhash, sig, err
		}

		// 对交易进行签名
		signedTx, err := enc.Porter().SigEvmTx(wg, tx, chainID)
		if err != nil {
			return txhash, sig, err
		}

		// 发送已签名的交易
		err = client.SendTransaction(context.Background(), signedTx)

		return signedTx.Hash().Hex(), sig, err
	}
}

func (t ChainConfig) HandlTransfer(to, mint string, amount *big.Int, wg *model.WalletGenerated, reqconf *hc.OpConfig) (txhash string, err error) {
	if len(t.GetRpc()) == 0 {
		return txhash, errors.New("rpc_config")
	}

	if wg.ChainCode == "SOLANA" {
		client := rpc.New(t.GetRpc()[0])
		fromAddr := solana.MustPublicKeyFromBase58(wg.Wallet)
		toAddr := solana.MustPublicKeyFromBase58(to)
		if mint == "" || mint == "SOL" {
			// SOL 主网币转账
			transaction := solana.Transaction{
				Message: solana.Message{
					Header: solana.MessageHeader{
						NumRequiredSignatures:       1,
						NumReadonlyUnsignedAccounts: 0,
						NumReadonlySignedAccounts:   0,
					},
					RecentBlockhash: solana.Hash{}, // 稍后将更新
				},
			}

			same2same := 0
			transaction.Message.AccountKeys = append(transaction.Message.AccountKeys, fromAddr)
			if fromAddr != toAddr {
				transaction.Message.AccountKeys = append(transaction.Message.AccountKeys, toAddr)
				same2same = 1
			}
			transaction.Message.AccountKeys = append(transaction.Message.AccountKeys, solana.MustPublicKeyFromBase58("11111111111111111111111111111111"))

			// SOL 转账指令
			transferInstruction := system.NewTransferInstruction(
				amount.Uint64(),
				fromAddr,
				toAddr,
			)
			data := transferInstruction.Build()
			dData, _ := data.Data()

			compiledTransferInstruction := solana.CompiledInstruction{
				ProgramIDIndex: uint16(2),
				Accounts: []uint16{
					0,
					uint16(same2same),
				},
				Data: dData, // 编译指令的数据
			}
			transaction.Message.Instructions = append(transaction.Message.Instructions, compiledTransferInstruction)

			outHash, _ := client.GetLatestBlockhash(context.Background(), rpc.CommitmentFinalized)
			transaction.Message.RecentBlockhash = outHash.Value.Blockhash

			messageHash, _ := transaction.Message.MarshalBinary()
			sig, err := enc.Porter().SigSol(wg, messageHash)
			if err != nil {
				return txhash, err
			}
			transaction.Signatures = []solana.Signature{solana.Signature(sig)}

			txbytes, _ := transaction.MarshalBinary()
			log.Info(base64.StdEncoding.EncodeToString(txbytes))

			txhash, err := client.SendTransaction(context.Background(), &transaction)
			return txhash.String(), err
		} else {
			fromAccount, _, _ := solana.FindAssociatedTokenAddress(fromAddr, solana.MustPublicKeyFromBase58(mint))
			toAccount, _, _ := solana.FindAssociatedTokenAddress(toAddr, solana.MustPublicKeyFromBase58(mint))

			transaction := solana.Transaction{
				Message: solana.Message{
					// 需要初始化头部信息
					Header: solana.MessageHeader{
						NumRequiredSignatures:       0, // 这稍后将更新
						NumReadonlyUnsignedAccounts: 0,
						NumReadonlySignedAccounts:   0,
					},
					RecentBlockhash: solana.Hash{}, // 这稍后将更新
				},
			}

			transaction.Message.AccountKeys = append(transaction.Message.AccountKeys,
				fromAddr, // 支付账户
				fromAccount,
				toAccount,                            // 要创建的 Token Account
				toAddr,                               // Token Account 所有者
				solana.MustPublicKeyFromBase58(mint), // Mint 地址
				solana.MustPublicKeyFromBase58("11111111111111111111111111111111"),            // 系统程序账户
				solana.MustPublicKeyFromBase58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"), // 关联 Token 程序
				solana.MustPublicKeyFromBase58("ComputeBudget111111111111111111111111111111"),
			)

			computeUnitPrice := uint64(16000000)
			computeUnitLimit := uint32(202000) // 设置为 202,000 计算单位
			if reqconf != nil {
				if reqconf.UnitPrice != nil && reqconf.UnitPrice.Uint64() > 0 {
					computeUnitPrice = reqconf.UnitPrice.Uint64()
				}
				if reqconf.UnitLimit != nil && reqconf.UnitLimit.Uint64() > 0 {
					computeUnitLimit = uint32(reqconf.UnitLimit.Uint64())
				}
			}
			setComputeUnitPriceIx := compute_budget.SetComputeUnitPrice{computeUnitPrice}
			cuData, _ := setComputeUnitPriceIx.Build().Data()
			compiledSetComputeUnitPriceIx := solana.CompiledInstruction{
				ProgramIDIndex: 7,          // ProgramID 的索引（通常放在 AccountKeys 第一个位置）
				Accounts:       []uint16{}, // 无需其他账户
				Data:           cuData,     // 指令数据
			}

			setComputeUnitLimitIx := compute_budget.SetComputeUnitLimit{computeUnitLimit}
			clData, _ := setComputeUnitLimitIx.Build().Data()
			compiledSetComputeUnitLimitIx := solana.CompiledInstruction{
				ProgramIDIndex: 7,          // ProgramID 的索引（通常放在 AccountKeys 第一个位置）
				Accounts:       []uint16{}, // 无需其他账户
				Data:           clData,     // 指令数据
			}

			transaction.Message.Instructions = append(transaction.Message.Instructions, compiledSetComputeUnitPriceIx, compiledSetComputeUnitLimitIx)

			toAccountInfo, _ := client.GetAccountInfo(context.Background(), toAccount)

			if toAccountInfo != nil {
				ownaddr := toAccountInfo.Value.Owner.String()
				log.Info(ownaddr)
			}

			if toAccountInfo == nil {
				transaction.Message.AccountKeys = append(
					transaction.Message.AccountKeys,
					solana.MustPublicKeyFromBase58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"),
				)
				createATAInstruction := associatedtokenaccount.NewCreateInstruction(
					transaction.Message.AccountKeys[0],
					toAddr,
					solana.MustPublicKeyFromBase58(mint),
				)
				data := createATAInstruction.Build()
				dData, _ := data.Data()

				compiledCreateAccountInstruction := solana.CompiledInstruction{
					ProgramIDIndex: uint16(8),
					Accounts: []uint16{
						0,
						2,
						3,
						4,
						5,
						6,
					},
					Data: dData, // 编译的数据
				}
				transaction.Message.Instructions = append(transaction.Message.Instructions, compiledCreateAccountInstruction)
			}

			transferInstruction := token.NewTransferInstruction(
				amount.Uint64(),
				fromAccount,
				toAccount,
				fromAddr,
				nil,
			)
			data := transferInstruction.Build()
			dData, _ := data.Data()
			compiledTransferInstruction := solana.CompiledInstruction{
				ProgramIDIndex: uint16(6),
				Accounts: []uint16{
					1,
					2,
					0,
				},
				Data: dData, // 编译的数据
			}
			transaction.Message.Instructions = append(transaction.Message.Instructions, compiledTransferInstruction)

			transaction.Message.Header.NumRequiredSignatures = 1
			transaction.Message.Header.NumReadonlyUnsignedAccounts = 0
			transaction.Message.Header.NumReadonlySignedAccounts = 0

			acs := make([]string, 0)
			for _, v := range transaction.Message.AccountKeys {
				acs = append(acs, v.String())
			}
			log.Info(acs)

			retryWithSameHash := false
			var outHash solana.Hash
			var sig []byte

			for retries := 0; retries < maxRetries; retries++ {
				if !retryWithSameHash {
					outHashResponse, err := client.GetLatestBlockhash(context.Background(), rpc.CommitmentProcessed)
					if err != nil {
						log.Errorf("Failed to get latest blockhash: %v", err)
						continue
					}
					outHash = outHashResponse.Value.Blockhash
					transaction.Message.RecentBlockhash = outHash

					messageHash, _ := transaction.Message.MarshalBinary()
					sig, err = enc.Porter().SigSol(wg, messageHash)
					if err != nil {
						return txhash, err
					}
					transaction.Signatures = []solana.Signature{solana.Signature(sig)}
				}

				txhash, err := client.SendTransaction(context.Background(), &transaction)

				if err == nil {
					txbytes, _ := transaction.MarshalBinary()
					base64tx := base64.StdEncoding.EncodeToString(txbytes)
					log.Infof("txhash: %s, transaction data: %s, recentBlockHash: %s", txhash.String(), base64tx, outHash.String())
					return txhash.String(), err
				}

				if strings.Contains(err.Error(), "Blockhash not found") {
					log.Info("Blockhash not found, retrying with same blockhash and signature...")
					retryWithSameHash = true
				} else {
					// 其他错误，重置 retryWithSameHash 并重新获取 blockhash 和签名
					log.Errorf("Send transaction failed: %v", err)
					retryWithSameHash = false
				}

				if retries == maxRetries-1 {
					log.Errorf("Transaction send failed after %d attempts: %v", 5, err)
					return "", err
				}
				time.Sleep(500 * time.Millisecond)
			}
			return "", err
		}
	} else {
		supp, evm := wallet.IsSupp(wallet.ChainCode(wg.ChainCode))
		if !supp {
			return txhash, errors.New("unsupport chain")
		}
		if !evm {
			return txhash, errors.New("unsupport chain")
		}

		toAddress := common.HexToAddress(to)
		tokenAddress := common.HexToAddress(mint)

		client, _ := ethclient.Dial(t.GetRpc()[0])
		if tokenAddress == (common.Address{}) {
			tx, err := sendETH(client, wg, toAddress, amount)
			if err != nil {
				log.Errorf("Failed to send ETH: %v", err)
				return "", err
			}
			return tx.Hash().Hex(), nil
		} else {
			tx, err := sendERC20(client, wg, toAddress, tokenAddress, amount)
			if err != nil {
				log.Errorf("Failed to send ERC20 token: %v", err)
				return "", err
			}
			return tx.Hash().Hex(), nil
		}
	}
}

func sendETH(client *ethclient.Client, wg *model.WalletGenerated, toAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	fromAddress := common.HexToAddress(wg.Wallet)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return nil, err
	}

	gasLimit := uint64(21000) // 转账ETH的固定Gas限制
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, err
	}

	tx := types.NewTransaction(nonce, toAddress, amount, gasLimit, gasPrice, nil)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, err
	}

	signedTx, err := enc.GetEP().SigEvmTx(wg, tx, chainID)
	//types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return nil, err
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return nil, err
	}

	return signedTx, nil
}

func sendERC20(client *ethclient.Client, wg *model.WalletGenerated, toAddress, tokenAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	fromAddress := common.HexToAddress(wg.Wallet)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return nil, err
	}

	parsedABI, err := abi.JSON(strings.NewReader(erc20ABI))
	if err != nil {
		return nil, err
	}

	// 创建ERC20转账的数据
	data, err := parsedABI.Pack("transfer", toAddress, amount)
	if err != nil {
		return nil, err
	}

	gasLimit := uint64(60000) // ERC20 转账的 Gas 限制，具体值视情况调整
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, err
	}

	tx := types.NewTransaction(nonce, tokenAddress, big.NewInt(0), gasLimit, gasPrice, data)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, err
	}

	signedTx, err := enc.GetEP().SigEvmTx(wg, tx, chainID) //types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return nil, err
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return nil, err
	}

	return signedTx, nil
}
